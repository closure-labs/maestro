#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The required context cannot consume stale or unreviewed same-SHA evidence."""
import copy
import json
import os
import unittest
from unittest import mock

from test_codeql_findings import API, REPO, HEAD
import codeql_findings as findings
import codeql_verdict as mod


class VerdictAPI(API):
    def __init__(self):
        super().__init__()
        self.runs[0].update(status='in_progress', conclusion=None)
        self.pull = {'state': 'open', 'head': {'sha': HEAD},
                     'base': {'ref': 'main', 'repo': {'full_name': REPO}}}
        self.reviews = [{'id': 7, 'user': {'id': 10, 'login': 'maintainer', 'type': 'User'},
                         'state': 'APPROVED', 'commit_id': HEAD, 'body': 'approved'}]
        self.record = dict(schema=1, repository=REPO, target=HEAD, head=HEAD, pullRequest=7,
                           run=42, attempt=1, digest='f' * 64,
                           artifacts=[[a['id'], a['digest']] for a in self.artifacts],
                           reviewsSha256=findings.review_snapshot(self, REPO, 7))
        self.checks = []
        self.publish()
        self.mutate = lambda endpoint: None

    def publish(self):
        self.checks = [dict(id=100, app={'id': mod.APP_ID}, name=mod.CHECK,
                            head_sha=HEAD, status='completed', conclusion='success',
                            external_id=f'codeql-v1:{self.record["run"]}:{self.record["attempt"]}:{self.record["digest"]}',
                            output={'summary': 'Eligible human decision verified.\n<!-- maestro-codeql-receipt '
                                               + json.dumps(self.record, sort_keys=True, separators=(',', ':')) + ' -->'})]

    def __call__(self, endpoint):
        if hasattr(self, 'mutate'):
            self.mutate(endpoint)
        if '/check-runs?' in endpoint:
            return copy.deepcopy({'total_count': len(self.checks), 'check_runs': self.checks})
        if endpoint == f'repos/{REPO}/actions/runs/42':
            return copy.deepcopy(self.runs[0])
        if endpoint == f'repos/{REPO}/pulls/7':
            return copy.deepcopy(self.pull)
        if '/reviews?' in endpoint:
            return copy.deepcopy(self.reviews)
        return copy.deepcopy(super().__call__(endpoint))

    def verify(self, attempt=1):
        return mod.verify(self, REPO, HEAD, 42, attempt, 'pull_request')


class Verdict(unittest.TestCase):
    def test_current_receipt_unblocks_before_whole_workflow_completion(self):
        api = VerdictAPI()
        self.assertEqual(api.runs[0]['status'], 'in_progress')
        self.assertTrue(api.verify())
        self.assertEqual(findings.wait_for_analysis(api, REPO, HEAD, 'pull_request')['id'], 42)

    def test_prior_same_sha_run_or_attempt_never_unblocks(self):
        for change in ({'run': 41}, {'attempt': 2}):
            api = VerdictAPI(); api.record.update(change); api.publish()
            self.assertFalse(api.verify())

    def test_failed_job_only_rerun_cannot_reuse_previous_scanners(self):
        api = VerdictAPI()
        api.runs[0]['run_attempt'] = 2
        api.record['attempt'] = 2; api.publish()
        with self.assertRaises(findings.authority.AuthorityError):
            api.verify(attempt=2)

    def test_foreign_app_or_name_and_unbound_green_check_are_not_authority(self):
        for mutate in (lambda a: a.checks[0].update(app={'id': 15368}),
                       lambda a: a.checks[0].update(name='Other check'),
                       lambda a: a.checks[0]['output'].update(summary='success'),
                       lambda a: a.checks[0].update(status='in_progress'),
                       lambda a: a.checks[0].update(conclusion='failure')):
            api = VerdictAPI(); mutate(api)
            with self.subTest(mutate=mutate):
                self.assertFalse(api.verify())

    def test_failed_cancelled_skipped_scanner_blocks(self):
        for conclusion in ('failure', 'cancelled', 'skipped', 'timed_out'):
            api = VerdictAPI(); api.jobs[2]['conclusion'] = conclusion
            with self.subTest(conclusion=conclusion), self.assertRaises(findings.authority.AuthorityError):
                api.verify()

    def test_reports_changed_or_expired_after_app_receipt_block(self):
        for mutate in (lambda a: a.artifacts[0].update(id=99),
                       lambda a: a.artifacts[0].update(digest='sha256:' + 'e' * 64),
                       lambda a: a.artifacts[0].update(expired=True),
                       lambda a: a.artifacts.pop()):
            api = VerdictAPI(); mutate(api)
            with self.subTest(mutate=mutate), self.assertRaises(findings.authority.AuthorityError):
                api.verify()

    def test_dismissal_edit_or_new_review_waits_for_fresh_app_decision(self):
        for mutate in (lambda a: a.reviews[0].update(state='DISMISSED'),
                       lambda a: a.reviews[0].update(body='withdrawn'),
                       lambda a: a.reviews.append(dict(a.reviews[0], id=8, state='CHANGES_REQUESTED'))):
            api = VerdictAPI(); mutate(api)
            with self.subTest(mutate=mutate):
                self.assertFalse(api.verify())

    def test_dismissal_during_artifact_verification_does_not_release_verdict(self):
        api = VerdictAPI()
        def mutate(endpoint):
            if '/artifacts?' in endpoint:
                api.reviews[0]['state'] = 'DISMISSED'
        api.mutate = mutate
        self.assertFalse(api.verify())

    def test_head_change_or_closed_pr_blocks(self):
        for mutate in (lambda a: a.pull['head'].update(sha='b' * 40),
                       lambda a: a.pull.update(state='closed')):
            api = VerdictAPI(); mutate(api)
            with self.subTest(mutate=mutate), self.assertRaises(findings.authority.AuthorityError):
                api.verify()

    def test_newer_scan_and_attempt_race_block(self):
        api = VerdictAPI(); api.runs.append(dict(api.runs[0], id=43))
        with self.assertRaises(findings.authority.AuthorityError):
            api.verify()
        api = VerdictAPI()
        def mutate(endpoint):
            if '/artifacts?' in endpoint:
                api.runs[0]['run_attempt'] = 2
        api.mutate = mutate
        with self.assertRaises(findings.authority.AuthorityError):
            api.verify()

    def test_superseding_authority_failure_during_verification_blocks(self):
        api = VerdictAPI()
        def mutate(endpoint):
            if '/artifacts?' in endpoint:
                api.checks.append(dict(api.checks[0], id=101, conclusion='failure'))
        api.mutate = mutate
        self.assertFalse(api.verify())

    def test_malformed_receipt_or_wrong_binding_blocks(self):
        for change in ({'target': 'b' * 40}, {'repository': 'other/repo'}, {'schema': True},
                       {'pullRequest': True}, {'head': 'invalid'}, {'digest': 'bad'}, {'extra': True}):
            api = VerdictAPI(); api.record.update(change); api.publish()
            with self.subTest(change=change), self.assertRaises(findings.authority.AuthorityError):
                api.verify()

    def test_missing_receipt_times_out_without_success(self):
        api = VerdictAPI(); api.checks = []
        ticks = iter([0, 1])
        with self.assertRaisesRegex(findings.authority.AuthorityError, 'timed out'):
            mod.wait(api, REPO, HEAD, 42, 1, 'pull_request', seconds=0,
                     clock=lambda: next(ticks), sleep=lambda _: self.fail('unexpected sleep'))

    def test_cancelled_source_does_not_wait_for_human_timeout(self):
        api = VerdictAPI(); api.runs[0].update(status='completed', conclusion='cancelled')
        with self.assertRaisesRegex(findings.authority.AuthorityError, 'cancelled'):
            mod.wait(api, REPO, HEAD, 42, 1, 'pull_request', sleep=lambda _: self.fail('unexpected sleep'))

    def test_exact_queue_identity_and_replacement(self):
        api = VerdictAPI(); queue = 'b' * 40
        api.runs[0].update(head_sha=queue, event='merge_group', head_branch='gh-readonly-queue/main/pr-7-abcdef0')
        for job in api.jobs:
            job['head_sha'] = queue
        for artifact in api.artifacts:
            artifact['workflow_run']['head_sha'] = queue
        api.record['target'] = queue; api.publish(); api.checks[0]['head_sha'] = queue
        def reader(endpoint):
            if '/git/ref/heads/' in endpoint:
                return {'object': {'sha': queue}}
            return api(endpoint)
        self.assertTrue(mod.verify(reader, REPO, queue, 42, 1, 'merge_group'))
        api.runs[0]['head_branch'] = 'gh-readonly-queue/main/pr-8-abcdef0'
        with self.assertRaises(findings.authority.AuthorityError):
            mod.verify(reader, REPO, queue, 42, 1, 'merge_group')

    def test_main_only_scans_do_not_invent_pr_authority(self):
        api = VerdictAPI(); api.runs[0]['event'] = 'push'
        with mock.patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/main'}):
            mod.wait(api, REPO, HEAD, 42, 1, 'push')
        with mock.patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/untrusted'}):
            with self.assertRaises(findings.authority.AuthorityError):
                mod.wait(api, REPO, HEAD, 42, 1, 'push')


if __name__ == '__main__':
    unittest.main()
