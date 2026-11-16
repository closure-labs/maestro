#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / 'modules/ci/authority/_source/decisions'))
spec = importlib.util.spec_from_file_location('check', ROOT / 'modules/ci/authority/_source/decisions/check.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
spec = importlib.util.spec_from_file_location('fixtures', ROOT / 'modules/ci/authority/_tests/decisions/test_authority.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
REPO, BOT, HEAD, MERGE = fixtures.REPO, fixtures.BOT, fixtures.HEAD, fixtures.MERGE


class GitHub(fixtures.GitHub):
    def __init__(self):
        super().__init__()
        self.pr.update(merged=False, state='open', merge_commit_sha=None)
        self.collector = {'path': mod.COLLECTOR, 'repository': {'full_name': REPO},
                          'status': 'completed', 'conclusion': 'success', 'event': 'pull_request',
                          'head_sha': HEAD, 'head_branch': 'feature', 'pull_requests': [{'number': 7}]}
        self.head_tree = {'truncated': False, 'tree': [{'path': self.files[0]['filename'],
                          'type': 'blob', 'mode': '100644', 'sha': 'd' * 40}]}
        self.queue_tree = self.head_tree
        self.queue_sha = MERGE
        self.queue_error = None
        self.queue_refs = []
        self.jobs = {'total_count': 1, 'jobs': [{'name': 'collect', 'status': 'completed', 'conclusion': 'success'}]}

    def __call__(self, endpoint):
        if '/jobs?' in endpoint:
            return self.jobs
        if '/actions/runs/' in endpoint:
            return self.collector
        if endpoint.endswith('?state=open&base=main&per_page=100&page=1'):
            return [{'number': 7}]
        if '/git/matching-refs/heads/gh-readonly-queue/' in endpoint:
            return self.queue_refs
        if '/git/ref/heads/gh-readonly-queue/' in endpoint:
            if self.queue_error:
                raise self.queue_error
            return {'object': {'sha': self.queue_sha}}
        if endpoint == f'repos/{REPO}/git/trees/{HEAD}?recursive=1':
            return self.head_tree
        if endpoint == f'repos/{REPO}/git/trees/{MERGE}?recursive=1':
            return self.queue_tree
        return super().__call__(endpoint)


class Checks(unittest.TestCase):
    def setUp(self):
        enabled = mock.patch.object(mod.codeql_findings, 'enabled', return_value=True)
        enabled.start(); self.addCleanup(enabled.stop)
        prepared = mock.patch.object(mod.codeql_findings, 'prepare',
                                      return_value={'count': 0, 'digest': 'f' * 64, 'workflowChanged': False})
        prepared.start(); self.addCleanup(prepared.stop)
        findings = mock.patch.object(mod.codeql_findings, 'enforce',
                                     return_value={'count': 0, 'digest': 'f' * 64, 'run': 42, 'attempt': 1, 'artifacts': []})
        self.findings = findings.start()
        self.addCleanup(findings.stop)
        patcher = mock.patch.object(mod, 'validate_proposal_packet', return_value={})
        self.packet_validator = patcher.start()
        self.addCleanup(patcher.stop)

    def test_preparation_preserves_legacy_authority_without_new_gate_or_receipt(self):
        api = GitHub(); api.files = [{'filename': '.github/workflows/ci.yml', 'status': 'modified'}]
        with mock.patch.object(mod.codeql_findings, 'enabled', return_value=False):
            result = mod.check_pr(REPO, 7, BOT, github=api)
        self.assertEqual(result['status'], 'authorized')
        self.assertIsNone(result['codeql'])
        self.assertIsNone(result['reviewsSha256'])
        self.findings.assert_not_called()

    def test_unmarked_codeql_wakeup_does_not_add_a_legacy_gate(self):
        api = GitHub(); api.collector['path'] = mod.codeql_findings.WORKFLOW
        with mock.patch.object(mod.codeql_findings, 'enabled', return_value=False), \
             mock.patch.object(mod, 'post_check') as post, \
             mock.patch.object(mod.codeql_findings, 'wait_for_analysis') as wait:
            self.assertEqual(mod.run_checks(REPO, 1, BOT, 123, api)['checks'], [])
        post.assert_not_called(); wait.assert_not_called()

    def test_regular_pr_passes_without_approval(self):
        api = GitHub()
        api.files = [{'filename': 'docs/operator.md', 'status': 'modified'}]
        api.reviews = []
        self.assertEqual(mod.check_pr(REPO, 7, BOT, github=api)['status'], 'not-required')

    def test_governance_requires_current_exact_human_review(self):
        api = GitHub()
        api.files = [{'filename': '.github/workflows/build.yml', 'status': 'modified'}]
        self.assertEqual(mod.check_pr(REPO, 7, BOT, github=api)['status'], 'authorized')
        api.reviews = []
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, github=api)

    def test_human_governance_author_allowed_but_human_proposal_author_rejected(self):
        api = GitHub()
        api.pr['user'] = {'id': 2, 'type': 'User', 'login': 'other'}
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, github=api)
        api.files = [{'filename': 'modules/ci/security/policy.nix', 'status': 'modified'}]
        self.assertEqual(mod.check_pr(REPO, 7, BOT, github=api)['status'], 'authorized')

    def test_exact_canonical_bot_proposal(self):
        self.assertEqual(mod.check_pr(REPO, 7, BOT, github=GitHub())['status'], 'authorized')

    def test_packet_validation_is_required_after_authority(self):
        self.packet_validator.side_effect = mod.authority.AuthorityError('Invalid immutable scan packet')
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, github=GitHub())
        self.packet_validator.assert_called_once_with(fixtures.PROPOSAL)

    def test_renamed_governed_path_cannot_hide_review_requirement(self):
        api = GitHub()
        api.files = [{'filename': 'docs/policy.txt', 'previous_filename': 'modules/ci/authority/policy.nix', 'status': 'renamed'}]
        api.reviews = []
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, github=api)

    def test_queue_requires_exact_reviewed_governed_tree(self):
        api = GitHub()
        self.assertEqual(mod.check_pr(REPO, 7, BOT, MERGE, api)['status'], 'authorized')
        api.queue_tree = {'truncated': False, 'tree': []}
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, MERGE, api)

    def test_queue_truncation_fails_closed(self):
        api = GitHub()
        api.queue_tree = {'truncated': True, 'tree': []}
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, MERGE, api)

    def test_collector_metadata_only_and_review_fallback(self):
        api = GitHub()
        self.assertEqual(mod.collector_targets(api.collector, REPO, api), [(7, None)])
        api.collector.update(event='pull_request_review', pull_requests=[])
        self.assertEqual(mod.collector_targets(api.collector, REPO, api), [(7, None)])
        api.collector['path'] = '.github/workflows/attacker.yml'
        with self.assertRaises(mod.authority.AuthorityError):
            mod.collector_targets(api.collector, REPO, api)

    def test_queue_identity_and_changed_ref_rejected(self):
        api = GitHub()
        api.collector.update(event='merge_group', head_branch='gh-readonly-queue/main/pr-7-abcdef0', head_sha=MERGE)
        self.assertEqual(mod.collector_targets(api.collector, REPO, api), [(7, MERGE)])
        api.queue_sha = HEAD
        with self.assertRaises(mod.authority.AuthorityError):
            mod.collector_targets(api.collector, REPO, api)
        api.collector['head_branch'] = 'attacker/pr-7-abcdef0'
        with self.assertRaises(mod.authority.AuthorityError):
            mod.collector_targets(api.collector, REPO, api)

    def retired_collector(self):
        api = GitHub()
        api.collector.update(event='merge_group', head_branch='gh-readonly-queue/main/pr-7-abcdef0', head_sha=MERGE)
        api.queue_error = mod.authority.AuthorityAPIError('Missing collector queue ref', 404)
        return api

    def test_authenticated_retired_queue_events_post_no_authority(self):
        for closed in (False, True):
            with self.subTest(closed=closed):
                api = self.retired_collector()
                if closed:
                    api.pr['state'] = 'closed'
                else:
                    api.queue_refs = [{'ref': 'refs/heads/gh-readonly-queue/main/pr-7-1234567',
                                       'object': {'type': 'commit', 'sha': HEAD}}]
                with mock.patch.object(mod, 'post_check') as post, mock.patch.object(mod, 'check_pr') as approval:
                    result = mod.run_checks(REPO, 1, BOT, 123, api)
                self.assertEqual(result['status'], 'obsolete')
                self.assertEqual(result['checks'], [])
                self.assertEqual(result['reason'], 'queue-pr-closed' if closed else 'queue-ref-replaced')
                post.assert_not_called()
                approval.assert_not_called()
                self.packet_validator.assert_not_called()

    def test_missing_queue_ref_without_unambiguous_proof_still_blocks(self):
        valid = {'ref': 'refs/heads/gh-readonly-queue/main/pr-7-1234567',
                 'object': {'type': 'commit', 'sha': HEAD}}
        cases = [[], None, [valid, valid], [None],
                 [dict(valid, ref='refs/heads/gh-readonly-queue/main/pr-8-1234567')],
                 [dict(valid, ref='refs/heads/feature')],
                 [dict(valid, ref='refs/heads/gh-readonly-queue/main/pr-7-abcdef0')],
                 [dict(valid, object={'type': 'tag', 'sha': HEAD})],
                 [dict(valid, object={'type': 'commit', 'sha': 'invalid'})],
                 [dict(valid, object={'type': 'commit', 'sha': MERGE})]]
        for refs in cases:
            with self.subTest(refs=refs):
                api = self.retired_collector()
                api.queue_refs = refs
                with mock.patch.object(mod, 'post_check') as post, self.assertRaises(mod.authority.AuthorityError):
                    mod.run_checks(REPO, 1, BOT, 123, api)
                post.assert_not_called()

    def test_api_failures_and_untrusted_collectors_cannot_be_ignored(self):
        for status in (None, 401, 403, 429, 500):
            with self.subTest(status=status):
                api = self.retired_collector()
                api.pr['state'] = 'closed'
                api.queue_error = mod.authority.AuthorityAPIError('Unavailable queue API', status)
                with mock.patch.object(mod, 'post_check') as post, self.assertRaises(mod.authority.AuthorityAPIError):
                    mod.run_checks(REPO, 1, BOT, 123, api)
                post.assert_not_called()
        for field, value in [('path', '.github/workflows/attacker.yml'), ('conclusion', 'failure'),
                             ('head_branch', 'attacker/pr-7-abcdef0'), ('head_sha', 'invalid')]:
            with self.subTest(field=field):
                api = self.retired_collector()
                api.pr['state'] = 'closed'
                api.collector[field] = value
                with mock.patch.object(mod, 'post_check') as post, self.assertRaises(mod.authority.AuthorityError):
                    mod.run_checks(REPO, 1, BOT, 123, api)
                post.assert_not_called()
        api = self.retired_collector()
        api.pr['base']['repo']['full_name'] = 'attacker/repo'
        with mock.patch.object(mod, 'post_check') as post, self.assertRaises(mod.authority.AuthorityError):
            mod.run_checks(REPO, 1, BOT, 123, api)
        post.assert_not_called()

    def test_app_origin_checked_and_missing_approval_posts_failure(self):
        api = GitHub()
        api.reviews = []
        calls = []
        def post(endpoint, body):
            calls.append((endpoint, body))
            return {'app': {'id': 123}}
        result = mod.run_checks(REPO, 1, BOT, 123, api, post)
        self.assertEqual(result['checks'][0]['status'], 'review-required')
        self.assertEqual(calls[0][1]['conclusion'], 'failure')
        with self.assertRaises(mod.authority.AuthorityError):
            mod.run_checks(REPO, 1, BOT, 999, api, post)

    def test_late_review_replaces_failure_with_fresh_success(self):
        api = GitHub()
        review = api.reviews[0]
        api.reviews = []
        calls = []
        def post(endpoint, body):
            calls.append(body)
            return {'app': {'id': 123}}
        mod.run_checks(REPO, 1, BOT, 123, api, post)
        api.collector.update(event='pull_request_review', pull_requests=[])
        api.reviews = [review]
        mod.run_checks(REPO, 2, BOT, 123, api, post)
        self.assertEqual([body['conclusion'] for body in calls], ['failure', 'success'])
        self.assertEqual([body['head_sha'] for body in calls], [HEAD, HEAD])
        self.assertEqual(self.packet_validator.call_count, 1)

    def test_review_completion_reconciles_previously_unapproved_proposal(self):
        import reconciliation
        api = GitHub()
        api.pr['node_id'] = 'PR_7'
        review = api.reviews.pop()
        cfg = {'repository': REPO, 'botLogin': BOT}
        value = {'mergeStateStatus': 'CLEAN', 'autoMergeRequest': {'enabledAt': 'now'}}
        workflow = (ROOT / 'modules/ci/authority/_tests/fixtures/retired-workflows/decisions.yml').read_text()
        self.assertIn('Continue Maestro release, Verify maintainer decision authority]', workflow)
        with mock.patch.object(reconciliation.authority, 'github_api', api), \
                mock.patch.object(reconciliation, 'required_check'), \
                mock.patch.object(reconciliation, 'queue_state', return_value=('waiting', value)) as state, \
                mock.patch.object(reconciliation, 'command') as command, \
                mock.patch.object(mod, 'post_check') as post:
            mod.run_checks(REPO, 1, BOT, 123, api)
            self.assertEqual(post.call_args.args[2], 'failure')
            self.assertEqual(reconciliation.queue_proposal(cfg, 7), 'awaiting-review')
            command.assert_not_called()
            api.collector.update(event='pull_request_review', pull_requests=[])
            api.reviews.append(review)
            mod.run_checks(REPO, 2, BOT, 123, api)
            self.assertEqual(post.call_args.args[2], 'success')
            state.side_effect = [('waiting', value), ('waiting', value), ('queued', value)]
            command.return_value = '{"data":{"enqueuePullRequest":{"mergeQueueEntry":{"id":"Q7"}}}}'
            self.assertEqual(reconciliation.queue_proposal(cfg, 7), 'queued')
            self.assertIn('head=' + HEAD, command.call_args.args[0])

    def test_comment_wakeup_rechecks_live_reviews_without_granting_authority(self):
        for event in ('issue_comment', 'pull_request_review_comment'):
            api = GitHub()
            api.collector.update(event=event, pull_requests=[])
            api.reviews = []
            with self.subTest(event=event), mock.patch.object(mod, 'post_check') as post:
                result = mod.run_checks(REPO, 1, BOT, 123, api)
                self.assertEqual(result['checks'][0]['status'], 'review-required')
                self.assertEqual(post.call_args.args[2], 'failure')

    def test_ordinary_issue_comment_does_not_post_authority(self):
        api = GitHub()
        api.collector['event'] = 'issue_comment'
        api.jobs['jobs'][0]['conclusion'] = 'skipped'
        with mock.patch.object(mod, 'post_check') as post:
            result = mod.run_checks(REPO, 1, BOT, 123, api)
        self.assertEqual(result['checks'], [])
        self.assertFalse(any('/pulls/' in endpoint for endpoint in api.calls))
        post.assert_not_called()

    def test_late_wakeup_rejects_stale_dismissed_ineligible_and_self_reviews(self):
        for case in ('stale', 'dismissed', 'changes-requested', 'role', 'team', 'self'):
            api = GitHub()
            api.collector.update(event='pull_request_review', pull_requests=[])
            if case == 'stale':
                api.reviews[0]['commit_id'] = 'd' * 40
            elif case == 'dismissed':
                api.reviews[0]['state'] = 'DISMISSED'
            elif case == 'changes-requested':
                api.reviews.append({**api.reviews[0], 'id': 11, 'state': 'CHANGES_REQUESTED'})
            elif case == 'role':
                api.roles['maintainer'] = 'write'
            elif case == 'team':
                api.members = []
            else:
                api.pr['user'] = dict(api.reviews[0]['user'])
            with self.subTest(case=case), mock.patch.object(mod, 'post_check') as post:
                result = mod.run_checks(REPO, 1, BOT, 123, api)
                self.assertEqual(result['checks'][0]['status'], 'review-required')
                self.assertEqual(post.call_args.args[2], 'failure')

    def test_head_races_never_publish_success_on_previously_selected_sha(self):
        # collector lookup, publisher selection, verifier entry, two author
        # reads, verifier final read, publisher final read.
        for change_at in (3, 6, 7):
            api = GitHub()
            api.files = [{'filename': 'modules/ci/security/policy.nix', 'status': 'modified'}]
            reads = 0
            def changing(endpoint):
                nonlocal reads
                if endpoint == f'repos/{REPO}/pulls/7':
                    reads += 1
                    if reads == change_at:
                        api.pr['head']['sha'] = 'd' * 40
                        api.reviews[0]['commit_id'] = 'd' * 40
                return api(endpoint)
            with self.subTest(change_at=change_at), mock.patch.object(mod, 'post_check') as post:
                result = mod.run_checks(REPO, 1, BOT, 123, changing)
                self.assertEqual(result['checks'][0]['status'], 'review-required')
                self.assertEqual(post.call_args.args[1:3], (HEAD, 'failure'))

    def test_review_or_role_withdrawn_during_packet_validation_blocks_success(self):
        for case in ('dismissed', 'role'):
            api = GitHub()
            def withdraw(proposal):
                if case == 'dismissed':
                    api.reviews[0]['state'] = 'DISMISSED'
                else:
                    api.roles['maintainer'] = 'write'
            self.packet_validator.side_effect = withdraw
            with self.subTest(case=case), mock.patch.object(mod, 'post_check') as post:
                mod.run_checks(REPO, 1, BOT, 123, api)
                self.assertEqual(post.call_args.args[2], 'failure')

    def test_security_authority_boundary_paths(self):
        for path in ('modules/ci/inventory/future-helper.py', 'modules/features/xo/storage.nix',
                     'modules/release/publication/commands.nix', 'host/settings.nix', 'flake.lock', 'flake.nix',
                     'devenv.lock', 'devenv.nix', 'secretspec.toml',
                     '.github/actions/setup-nix/action.yml', 'automation/decisions/security/fixture.json'):
            self.assertTrue(mod.governed(path), path)
        for path in ('.gitleaks.toml', 'gitleaks.toml', '.gitleaksignore'):
            self.assertTrue(mod.governed(path), path)
        self.assertFalse(mod.governed('docs/README.md'))


class FindingsIntegration(unittest.TestCase):
    def setUp(self):
        enabled = mock.patch.object(mod.codeql_findings, 'enabled', return_value=True)
        enabled.start(); self.addCleanup(enabled.stop)
        report = {'count': 1, 'digest': 'f' * 64, 'workflowChanged': False, 'run': 42, 'attempt': 1, 'artifacts': []}
        patcher = mock.patch.object(mod.codeql_findings, 'evidence', return_value=report)
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(mod.codeql_findings, 'wait_for_analysis', return_value={})
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(mod.codeql_findings, 'latest_run', return_value={'id': 42, 'run_attempt': 1})
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(mod.codeql_findings, 'artifact_snapshot', return_value=[])
        patcher.start(); self.addCleanup(patcher.stop)

    def api(self):
        api = GitHub()
        api.files = [{'filename': '.github/workflows/ci.yml', 'status': 'modified'}]
        api.reviews[-1]['body'] = f'/maestro accept-codeql {HEAD} ' + 'f' * 64
        return api

    def test_first_blocked_check_displays_one_combined_approval_command(self):
        api = self.api()
        api.reviews = []
        with self.assertRaises(mod.authority.HumanDecisionRequired) as blocked:
            mod.check_pr(REPO, 7, BOT, github=api)
        self.assertIn(f'/maestro accept-codeql {HEAD} ' + 'f' * 64, str(blocked.exception))

    def test_report_ready_callback_precedes_missing_governance_approval(self):
        api = self.api(); api.reviews = []
        announce = mock.Mock()
        with self.assertRaises(mod.authority.HumanDecisionRequired):
            mod.check_pr(REPO, 7, BOT, github=api, report_ready=announce)
        self.assertEqual(announce.call_count, 1)
        self.assertEqual(announce.call_args.args[:2], (7, HEAD))
        self.assertEqual(announce.call_args.args[2]['count'], 1)

    def test_announcement_is_non_authorizing_and_duplicate_exact_report_is_reused(self):
        api = self.api(); report = mod.codeql_findings.evidence()
        calls = []
        def post(endpoint, body):
            calls.append(body)
            return dict(body, id=81, app={'id': 5384448})
        with mock.patch.object(mod.codeql_findings, 'ready_checks', return_value=[]):
            mod.announce_report(REPO, 7, HEAD, report, 5384448, api, post)
        self.assertEqual(calls[0]['conclusion'], 'neutral')
        self.assertEqual(calls[0]['name'], 'CodeQL findings ready')
        self.assertNotIn('maestro-codeql-receipt ', calls[0]['output']['summary'])
        record = mod.codeql_findings.ready_record(REPO, 7, HEAD, report)
        with mock.patch.object(mod.codeql_findings, 'ready_checks', return_value=[(81, None, record)]):
            mod.announce_report(REPO, 7, HEAD, report, 5384448, api, post)
        self.assertEqual(len(calls), 1)

    def test_single_live_approval_satisfies_both_gates(self):
        result = mod.check_pr(REPO, 7, BOT, github=self.api())
        self.assertEqual(result['status'], 'authorized')
        self.assertEqual(result['codeql']['count'], 1)

    def test_ordinary_approval_and_dismissal_do_not_satisfy_findings(self):
        for mutate in (lambda a: a.reviews[-1].update(body='approved'),
                       lambda a: a.reviews[-1].update(state='DISMISSED'),
                       lambda a: a.reviews[-1].update(commit_id='e' * 40),
                       lambda a: a.roles.update(maintainer='read')):
            api = self.api(); mutate(api)
            with self.subTest(mutation=mutate), self.assertRaises(mod.authority.AuthorityError):
                mod.check_pr(REPO, 7, BOT, github=api)

    def test_codeql_completion_targets_live_pr_only(self):
        api = self.api()
        run = dict(api.collector, path=mod.codeql_findings.WORKFLOW)
        self.assertEqual(mod.collector_targets(run, REPO, api), [(7, None)])
        run['head_sha'] = 'e' * 40
        self.assertEqual(mod.collector_targets(run, REPO, api), [])
        run.update(head_sha=HEAD, pull_requests=[])
        with self.assertRaises(mod.authority.AuthorityError):
            mod.collector_targets(run, REPO, api)

    def test_review_wakes_current_queue_and_ambiguous_refs_block(self):
        api = self.api()
        ref = {'ref': 'refs/heads/gh-readonly-queue/main/pr-7-abcdef0',
               'object': {'type': 'commit', 'sha': MERGE}}
        api.queue_refs = [ref]
        self.assertEqual(mod.with_live_queue_targets([(7, None)], REPO, api), [(7, None), (7, MERGE)])
        api.queue_refs.append(ref)
        with self.assertRaises(mod.authority.AuthorityError):
            mod.with_live_queue_targets([(7, None)], REPO, api)

    def test_codeql_pr_wakeup_uses_queue_event_for_queue_target(self):
        api = self.api()
        api.collector['path'] = mod.codeql_findings.WORKFLOW
        api.queue_refs = [{'ref': 'refs/heads/gh-readonly-queue/main/pr-7-abcdef0',
                           'object': {'type': 'commit', 'sha': MERGE}}]
        results = [dict(target=target, head=HEAD, status='authorized', codeql=None,
                        reviewsSha256=None) for target in (HEAD, MERGE)]
        with mock.patch.object(mod, 'check_pr', side_effect=results), \
                mock.patch.object(mod, 'post_check'), \
                mock.patch.object(mod.codeql_findings, 'wait_for_analysis') as wait:
            mod.run_checks(REPO, 1, BOT, 5384448, api)
        self.assertEqual(wait.call_args_list, [mock.call(api, REPO, HEAD, 'pull_request'),
                                              mock.call(api, REPO, MERGE, 'merge_group')])

    def test_findings_failure_posts_app_bound_failure(self):
        api = self.api()
        api.reviews[-1]['body'] = '/maestro accept-codeql wrong'
        calls = []
        def post(endpoint, body):
            calls.append(body)
            return {'app': {'id': 5384448}}
        with mock.patch.object(mod, 'announce_report'):
            mod.run_checks(REPO, 1, BOT, 5384448, api, post)
        self.assertEqual(calls[0]['conclusion'], 'failure')
        self.assertIn('/maestro accept-codeql', calls[0]['output']['summary'])


if __name__ == '__main__':
    unittest.main()
