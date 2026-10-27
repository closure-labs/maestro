#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reject missing, interrupted or unjustifiably skipped split-job obligations."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

VERDICT = Path(os.environ.get('MAESTRO_VERDICT_SOURCE', Path(__file__).parents[4] / 'modules/ci/checks/_source/verdict.sh'))


def route(mode):
    required = mode != 'skip'
    return dict(schema_version=4, retained_evidence=None, publish_required=False, qualification=dict(
        required=required, mode=mode, artifact_run_id=1 if required else None,
        media_run_id=1 if required else None, evidence_run_id=1 if required else None,
        media_input='a' * 64 if required else None, evidence_input='b' * 64 if required else None))


class VerdictTests(unittest.TestCase):
    def execute(self, mode='qualify-media', **changes):
        env = dict(os.environ, ROUTE_RESULT='success', AUDIT_REQUIRED='true', AUDIT_RESULT='success',
                   EQUIVALENCE_RESULT='success', COMPARISON_REQUIRED='true', COMPARISON_RESULT='success', SPLIT_QUALIFICATION='true', CI_PLAN=json.dumps(route(mode)),
                   GITHUB_EVENT_NAME='pull_request', GITHUB_REF='refs/pull/1/merge', GITHUB_SHA='c' * 40,
                   GITHUB_REPOSITORY='closure-labs/maestro', GITHUB_RUN_ID='1', GITHUB_RUN_ATTEMPT='1', MAESTRO_DECISION_ONLY_REUSE_ENABLED='false',
                   APPLIANCE_RESULT='success', INSTALLER_RESULT='success', QUALIFICATION_RESULT='success',
                   BOOT_RESULT='success', SCAN_RESULT='success', SECURITY_RESULT='success', SIGNING_RESULT='skipped',
                   GRAPH_RESULT_REQUIRED='false')
        if mode in ('reuse', 'skip'):
            env.update(APPLIANCE_RESULT='skipped', INSTALLER_RESULT='skipped')
        if mode == 'refresh-evidence':
            env['INSTALLER_RESULT'] = 'skipped'
        if mode == 'skip':
            env.update(QUALIFICATION_RESULT='skipped', BOOT_RESULT='skipped', SCAN_RESULT='skipped', SECURITY_RESULT='skipped',
                       GITHUB_EVENT_NAME='workflow_dispatch', VALIDATE_ONLY='true')
        env.update(changes)
        with tempfile.TemporaryDirectory() as work:
            if 'CI_RESULT_SHA256' in changes and changes['CI_RESULT_SHA256'] != 'missing':
                result = dict(schemaVersion=1, planSha256='d' * 64, producer={
                    'GITHUB_REPOSITORY': env['GITHUB_REPOSITORY'], 'GITHUB_SHA': env['GITHUB_SHA'], 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'},
                    completeValidationRequired=True, schedulingMode=changes.get('RESULT_SCHEDULING_MODE', 'shadow'))
                data = json.dumps(result).encode()
                (Path(work) / 'ci-result.json').write_bytes(data)
                if changes['CI_RESULT_SHA256'] == 'valid':
                    env['CI_RESULT_SHA256'] = hashlib.sha256(data).hexdigest()
            return subprocess.run(['bash', str(VERDICT)], cwd=work, env=env, capture_output=True).returncode

    def test_each_route_requires_all_applicable_results(self):
        for mode in ('qualify-media', 'qualify-media-reuse-evidence', 'refresh-evidence', 'reuse', 'skip'):
            with self.subTest(mode=mode):
                self.assertEqual(self.execute(mode), 0)

    def test_missing_interrupted_or_unjustified_skips_rejected(self):
        for key in ('ROUTE_RESULT', 'AUDIT_RESULT', 'EQUIVALENCE_RESULT', 'COMPARISON_RESULT', 'APPLIANCE_RESULT', 'INSTALLER_RESULT',
                    'QUALIFICATION_RESULT', 'BOOT_RESULT', 'SCAN_RESULT', 'SECURITY_RESULT'):
            for status in ('', 'failure', 'cancelled', 'skipped'):
                with self.subTest(key=key, status=status):
                    self.assertNotEqual(self.execute(**{key: status}), 0)

    def test_paths_and_force_controls_cannot_justify_skipped_qualification(self):
        self.assertNotEqual(self.execute('skip', GITHUB_EVENT_NAME='pull_request'), 0)
        self.assertNotEqual(self.execute('skip', GITHUB_EVENT_NAME='merge_group'), 0)
        self.assertNotEqual(self.execute('skip', VALIDATE_ONLY='false'), 0)
        self.assertNotEqual(self.execute('skip', FORCE_BUILD='true'), 0)
        self.assertNotEqual(self.execute('skip', FORCE_ARTIFACT='true'), 0)

    def test_merge_queue_never_signs_and_main_requires_signing(self):
        self.assertEqual(self.execute(GITHUB_EVENT_NAME='merge_group', GITHUB_REF='refs/heads/gh-readonly-queue/main/pr-1'), 0)
        self.assertNotEqual(self.execute(GITHUB_EVENT_NAME='merge_group', SIGNING_RESULT='success'), 0)
        self.assertNotEqual(self.execute(GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main'), 0)
        self.assertEqual(self.execute(GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', SIGNING_RESULT='success'), 0)

    def test_bound_result_missing_or_corrupt_cannot_satisfy_gate(self):
        self.assertEqual(self.execute(GRAPH_RESULT_REQUIRED='true', CI_RESULT_SHA256='valid', CI_GRAPH_PLAN_SHA256='d' * 64), 0)
        for digest in ('missing', 'f' * 64):
            self.assertNotEqual(self.execute(GRAPH_RESULT_REQUIRED='true', CI_RESULT_SHA256=digest, CI_GRAPH_PLAN_SHA256='d' * 64), 0)
        self.assertNotEqual(self.execute(GRAPH_RESULT_REQUIRED='true', CI_RESULT_SHA256='valid', CI_GRAPH_PLAN_SHA256='f' * 64), 0)

    def test_scheduling_mode_must_match_planned_protected_result(self):
        bound = dict(GRAPH_RESULT_REQUIRED='true', CI_RESULT_SHA256='valid', CI_GRAPH_PLAN_SHA256='d' * 64)
        self.assertNotEqual(self.execute(**bound, RESULT_SCHEDULING_MODE='active'), 0)
        self.assertNotEqual(self.execute(**bound, GRAPH_SCHEDULING_MODE='active'), 0)
        self.assertEqual(self.execute(**bound, GRAPH_SCHEDULING_MODE='active', RESULT_SCHEDULING_MODE='active'), 0)
        self.assertNotEqual(self.execute(**bound, GRAPH_SCHEDULING_MODE='unknown'), 0)

    def test_legacy_plan_still_requires_full_audit(self):
        value = route('qualify-media')
        value.pop('retained_evidence')
        value['schema_version'] = 3
        self.assertEqual(self.execute(CI_PLAN=json.dumps(value)), 0)
        self.assertNotEqual(self.execute(CI_PLAN=json.dumps(value), AUDIT_RESULT='skipped'), 0)


if __name__ == '__main__':
    unittest.main()
