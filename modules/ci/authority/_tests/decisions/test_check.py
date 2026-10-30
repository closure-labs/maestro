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
        patcher = mock.patch.object(mod, 'validate_proposal_packet', return_value={})
        self.packet_validator = patcher.start()
        self.addCleanup(patcher.stop)

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
        workflow = (ROOT / '.github/workflows/decisions.yml').read_text()
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


if __name__ == '__main__':
    unittest.main()
