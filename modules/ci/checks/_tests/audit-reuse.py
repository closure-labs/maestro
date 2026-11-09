#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact-commit queue audit reuse is optional, bounded and fail closed."""
import copy
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('audit_reuse', ROOT / 'modules/ci/checks/_source/audit-reuse.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NOW = dt.datetime(2026, 11, 9, 16, tzinfo=dt.timezone.utc)
REPO = 'closure-labs/maestro'
SHA = 'a' * 40


def fixtures():
    run = dict(id=123, run_attempt=2, repository=dict(id=42, full_name=REPO),
               head_repository=dict(id=42, full_name=REPO), event='merge_group',
               head_sha=SHA, path='.github/workflows/ci.yml', status='completed', conclusion='success',
               updated_at='2026-11-09T15:50:00Z', run_started_at='2026-11-09T15:00:00Z',
               html_url='https://github.com/' + REPO + '/actions/runs/123')
    rows = [dict(attribute='check' + str(i), name='name' + str(i), status='success',
                 outputs=['/nix/store/' + 'a' * 32 + '-check' + str(i)]) for i in range(20)]
    audit = json.dumps(dict(schemaVersion=2, plan='maestro-validation', targetCount=20,
                            failureCount=0, results=rows)).encode()
    timings = json.dumps(dict(schemaVersion=1, plan='maestro-validation', results=[])).encode()
    reference = dict(schemaVersion=1, producer=dict(GITHUB_REPOSITORY=REPO, GITHUB_SHA=SHA,
                     GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2'), graphSha256='b' * 64,
                     planSha256='c' * 64, auditSha256=module.digest(audit), timingsSha256=module.digest(timings))
    values = {'audit.json': audit, 'timings.json': timings, 'reference.json': json.dumps(reference).encode()}
    archive = make_zip(values)
    artifact = dict(id=456, name='maestro-audit-audit', expired=False, size_in_bytes=len(archive),
                    digest='sha256:' + module.digest(archive), created_at='2026-11-09T15:40:00Z',
                    expires_at='2026-12-09T15:40:00Z', workflow_run=dict(id=123, head_sha=SHA,
                    repository_id=42, head_repository_id=42))
    jobs = [dict(name='Repository checks', run_attempt=2, conclusion='success', steps=[
                dict(name='Validate repository', conclusion='success'),
                dict(name='Bind complete audit reference to this candidate and attempt', conclusion='success')]),
            dict(name='Required CI verdict', conclusion='success', run_attempt=2)]
    return run, artifact, jobs, values, archive


def make_zip(values):
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w') as zipped:
        for name, value in values.items():
            zipped.writestr(name, value)
    return result.getvalue()


class ReuseTests(unittest.TestCase):
    def test_eligibility_is_main_push_only(self):
        good = dict(GITHUB_ACTIONS='true', GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main',
                    GITHUB_SHA=SHA, GITHUB_REPOSITORY=REPO, GH_TOKEN='test')
        self.assertTrue(module.eligible(good))
        for key, value in [('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_EVENT_NAME', 'merge_group'),
                           ('GITHUB_EVENT_NAME', 'workflow_dispatch'), ('GITHUB_EVENT_NAME', 'schedule'),
                           ('GITHUB_REF', 'refs/heads/other'), ('GITHUB_ACTIONS', 'false'),
                           ('GITHUB_SHA', 'main'), ('GITHUB_REPOSITORY', '../other'), ('GH_TOKEN', '')]:
            with self.subTest(key=key, value=value):
                self.assertFalse(module.eligible(dict(good, **{key: value})))

    def test_valid_source(self):
        run, artifact, jobs, values, archive = fixtures()
        module.verify_run(run, REPO, SHA, NOW)
        module.verify_jobs(jobs, 2)
        module.verify_artifact(artifact, run, REPO, SHA, NOW)
        self.assertEqual(module.unpack(archive, artifact, run, REPO, SHA), values)

    def test_wrong_source_run_fails(self):
        for key, value in [('event', 'pull_request'), ('head_sha', 'd' * 40),
                           ('path', '.github/workflows/other.yml'), ('status', 'in_progress'),
                           ('conclusion', 'failure'), ('run_attempt', 0),
                           ('repository', dict(full_name='attacker/fork')), ('head_repository', dict(full_name='attacker/fork')),
                           ('updated_at', '2026-11-07T15:50:00Z'), ('updated_at', '2026-11-10T15:50:00Z')]:
            run = fixtures()[0]
            run[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.verify_run(run, REPO, SHA, NOW)

    def test_old_attempt_missing_and_failed_steps_rejected(self):
        for mutate in [lambda j: j[0].update(run_attempt=1), lambda j: j[0].update(conclusion='failure'),
                       lambda j: j[0]['steps'].pop(), lambda j: j.pop(),
                       lambda j: j[0]['steps'][0].update(conclusion='skipped')]:
            jobs = fixtures()[2]
            mutate(jobs)
            with self.assertRaises(ValueError):
                module.verify_jobs(jobs, 2)

    def test_split_execution_binding_supported(self):
        jobs = fixtures()[2]
        execute = dict(name='Execute repository validation', run_attempt=2, conclusion='success',
                       steps=[jobs[0]['steps'].pop(0)])
        module.verify_jobs([*jobs, execute], 2)

    def test_artifact_identity_freshness_and_size(self):
        for key, value in [('expired', True), ('digest', None), ('size_in_bytes', module.MAX_ARCHIVE + 1),
                           ('workflow_run', dict(id=123, head_sha=SHA, repository_id=42, head_repository_id=99)),
                           ('created_at', '2026-11-09T14:40:00Z'), ('expires_at', '2026-11-09T15:59:00Z')]:
            run, artifact, *_ = fixtures()
            artifact[key] = value
            with self.subTest(key=key), self.assertRaises((ValueError, TypeError)):
                module.verify_artifact(artifact, run, REPO, SHA, NOW)

    def test_corrupted_archive_and_reference_rejected(self):
        run, artifact, _, values, archive = fixtures()
        with self.assertRaises(ValueError):
            module.unpack(archive + b'x', artifact, run, REPO, SHA)
        for field, value in [('producer', {}), ('auditSha256', '0' * 64), ('reuseSha256', 'f' * 64),
                             ('graphSha256', 'bad')]:
            changed = dict(values)
            reference = json.loads(values['reference.json'])
            reference[field] = value
            changed['reference.json'] = json.dumps(reference).encode()
            archive = make_zip(changed)
            artifact['digest'] = 'sha256:' + module.digest(archive)
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.unpack(archive, artifact, run, REPO, SHA)

    def test_incomplete_or_duplicate_outputs_rejected(self):
        for mutate in [lambda a: a.update(failureCount=1), lambda a: a['results'].pop(),
                       lambda a: a['results'][0].update(status='failure'),
                       lambda a: a['results'][0].update(outputs=[]),
                       lambda a: a['results'][0].update(attribute='check1')]:
            run, artifact, _, values, _ = fixtures()
            audit = json.loads(values['audit.json'])
            mutate(audit)
            values['audit.json'] = json.dumps(audit).encode()
            reference = json.loads(values['reference.json'])
            reference['auditSha256'] = module.digest(values['audit.json'])
            values['reference.json'] = json.dumps(reference).encode()
            archive = make_zip(values)
            artifact['digest'] = 'sha256:' + module.digest(archive)
            with self.assertRaises(ValueError):
                module.unpack(archive, artifact, run, REPO, SHA)

    def test_restore_is_bound_and_does_not_copy_old_reference(self):
        run, artifact, jobs, values, archive = fixtures()
        with tempfile.TemporaryDirectory() as temporary:
            env = dict(GITHUB_REPOSITORY=REPO, GITHUB_SHA=SHA,
                       MAESTRO_CI_AUDIT_MANIFEST=temporary + '/audit.json',
                       MAESTRO_CI_AUDIT_TIMINGS=temporary + '/timings.json')
            responses = [dict(workflow_runs=[run]), run, dict(total_count=len(jobs), jobs=jobs),
                         dict(total_count=1, artifacts=[artifact]), run, artifact]
            with patch.object(module, 'api', side_effect=responses), patch.object(module, 'download', return_value=archive):
                self.assertTrue(module.restore(env, NOW))
            self.assertEqual((Path(temporary) / 'audit.json').read_bytes(), values['audit.json'])
            self.assertFalse((Path(temporary) / 'reference.json').exists())
            receipt = json.loads((Path(temporary) / 'reuse.json').read_text())
            self.assertEqual(receipt['sourceProducer']['GITHUB_SHA'], SHA)

    def test_rerun_during_transfer_falls_back(self):
        run, artifact, jobs, _, archive = fixtures()
        changed = dict(run, run_attempt=3)
        with tempfile.TemporaryDirectory() as temporary:
            env = dict(GITHUB_REPOSITORY=REPO, GITHUB_SHA=SHA,
                       MAESTRO_CI_AUDIT_MANIFEST=temporary + '/audit.json',
                       MAESTRO_CI_AUDIT_TIMINGS=temporary + '/timings.json')
            responses = [dict(workflow_runs=[run]), run, dict(total_count=len(jobs), jobs=jobs),
                         dict(total_count=1, artifacts=[artifact]), changed]
            with patch.object(module, 'api', side_effect=responses), patch.object(module, 'download', return_value=archive):
                self.assertFalse(module.restore(env, NOW))
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_workflow_preserves_full_audit_and_signing(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('ci:repository-audit', workflow)
        self.assertIn('ci:graph:reference', workflow)
        self.assertIn('ci:qualification:sign-check', workflow)
        self.assertIn('ci:graph:result', workflow)
        self.assertNotIn('require-sigs = false', workflow)
        source = (ROOT / 'modules/ci/checks/_source/repository-audit.sh').read_text()
        self.assertLess(source.index('maestro-ci-security-inventory-preflight'), source.index('if maestro-ci-audit-reuse'))
        self.assertIn('nix flake check', source)


if __name__ == '__main__':
    unittest.main()
