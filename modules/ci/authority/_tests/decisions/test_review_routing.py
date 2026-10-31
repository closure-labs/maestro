# SPDX-License-Identifier: Apache-2.0
"""Measure targeted review routing while exercising unchanged fresh authority."""
from copy import deepcopy
import re
import unittest
from test_check import GitHub, mod, REPO, BOT, HEAD

REPOSITORY = {'id': 91, 'full_name': REPO}


class API:
    def __init__(self, count=1, governed=True, verified=True):
        self.pulls = {number: GitHub() for number in range(7, 7+count)}
        for number, api in self.pulls.items():
            head = HEAD if number == 7 else f'{number:040x}'
            api.pr.update(number=number)
            api.pr['head'].update(sha=head, ref=f'feature-{number}', repo=deepcopy(REPOSITORY))
            api.pr['base']['repo'] = deepcopy(REPOSITORY)
            for review in api.reviews:
                review['commit_id'] = head
            api.files = [{'filename': '.github/workflows/ci.yml' if governed else 'docs/operator.md',
                          'status': 'modified'}]
        self.collector = deepcopy(self.pulls[7].collector)
        self.collector.update(id=42, run_attempt=1, workflow_id=5, event='pull_request_review',
                              head_branch='feature-7', pull_requests=[],
                              repository=deepcopy(REPOSITORY), head_repository=deepcopy(REPOSITORY))
        if not verified:
            del self.collector['run_attempt']  # Legacy metadata takes the original global path.
        self.workflow = {'id': 5, 'path': mod.COLLECTOR, 'state': 'active'}
        self.associated = [{'number': 7}]
        self.calls, self.posts = [], []
        self.mutate = lambda endpoint: None
        self.failure = None

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        self.mutate(endpoint)
        if self.failure and '/commits/' in endpoint:
            raise self.failure
        if '/actions/runs/' in endpoint:
            return deepcopy(self.collector)
        if '/actions/workflows/' in endpoint:
            return deepcopy(self.workflow)
        if '/commits/' in endpoint:
            return deepcopy(self.associated)
        if endpoint.endswith('?state=open&base=main&per_page=100&page=1'):
            return [{'number': number} for number in self.pulls]
        match = re.search(r'/pulls/([0-9]+)', endpoint)
        if match:
            number = int(match[1])
            return deepcopy(self.pulls[number](endpoint.replace('/pulls/'+str(number), '/pulls/7')))
        return deepcopy(self.pulls[7](endpoint))

    def post(self, endpoint, body):
        self.posts.append((endpoint, body))
        return {'app': {'id': 5384448}}

    def check(self):
        return mod.run_checks(REPO, 42, BOT, 5384448, github=self, api_post=self.post)

    def routed(self):
        return mod.collector_targets(deepcopy(self.collector), REPO, self, collector_run_id=42)


class ReviewRouting(unittest.TestCase):
    def test_measured_gets_and_writes_for_one_five_ten_open_prs(self):
        for governed in (False, True):
            per_pr = 26 if governed else 6
            for count in (1, 5, 10):
                baseline = API(count, governed, verified=False)
                old = baseline.check()
                self.assertEqual(len(baseline.calls), 2 + per_pr * count)
                self.assertEqual(len(baseline.posts), count)
                self.assertTrue(all(v['status'] == ('authorized' if governed else 'not-required') for v in old['checks']))
                targeted = API(count, governed)
                result = targeted.check()
                self.assertEqual([v['pullRequest'] for v in result['checks']], [7])
                self.assertEqual(len(targeted.posts), 1)
                self.assertEqual(len(targeted.calls), per_pr + 4)
                self.assertEqual(targeted.posts[0][1]['head_sha'], HEAD)
                self.assertFalse(any('state=open&base=main' in call for call in targeted.calls))
                # Final canonical PR reads and repeated live review/membership
                # reads remain, irrespective of how many unrelated PRs exist.
                self.assertEqual(sum(call.endswith('/pulls/7') for call in targeted.calls), 7 if governed else 5)
                if governed:
                    self.assertEqual(sum('/reviews?' in call for call in targeted.calls), 2)
                    self.assertEqual(sum('/memberships/' in call for call in targeted.calls), 4)

    def test_missing_spoofed_capped_or_ambiguous_association_retains_global_checks(self):
        changes = [lambda a: setattr(a, 'associated', []),
                   lambda a: setattr(a, 'associated', [{'number': 8}]),
                   lambda a: setattr(a, 'associated', [{'number': 7}] * 100),
                   lambda a: setattr(a, 'associated', [{'number': 7}] * 2),
                   lambda a: setattr(a, 'associated', [{'number': True}]),
                   lambda a: setattr(a, 'associated', {'number': 7}),
                   lambda a: a.workflow.update(path='.github/workflows/evil.yml'),
                   lambda a: a.workflow.update(id=6),
                   lambda a: a.workflow.update(state='disabled_manually'),
                   lambda a: a.collector.update(head_repository={'id': 5,'full_name': 'other/fork'}),
                   lambda a: a.collector.update(head_branch='spoofed'),
                   lambda a: a.pulls[7].pr['head']['repo'].update(id=5),
                   lambda a: a.pulls[7].pr['base']['repo'].update(id=5),
                   lambda a: a.collector.update(run_attempt=None),
                   lambda a: a.collector.update(id=43)]
        for change in changes:
            api = API(count=5); change(api)
            result = api.check()
            self.assertEqual({v['pullRequest'] for v in result['checks']}, set(range(7,12)))
            self.assertEqual(len(api.posts), 5)
        api = API(count=5)
        api.pulls[8].pr['head'] = deepcopy(api.pulls[7].pr['head'])
        api.associated = [{'number':7},{'number':8}]
        self.assertEqual({number for number, target in api.routed()}, set(range(7,12)))

    def test_untrusted_collector_origin_fails_before_routing_or_writes(self):
        for changes in ({'path':'.github/workflows/evil.yml'}, {'event':'workflow_dispatch'},
                        {'repository':{'id':91,'full_name':'other/repository'}}, {'conclusion':'failure'}):
            api = API(count=5); api.collector.update(changes)
            with self.assertRaises(mod.authority.AuthorityError):
                api.check()
            self.assertFalse(api.posts)
            self.assertEqual(len(api.calls), 1)

    def test_transport_permission_failures_do_not_retry_via_another_route(self):
        for status in (401,403,429,503):
            api = API(5); api.failure = mod.authority.AuthorityAPIError('Unavailable', status)
            with self.assertRaises(mod.authority.AuthorityAPIError): api.check()
            self.assertFalse(api.posts)
            self.assertFalse(any('state=open&base=main' in call for call in api.calls))

    def test_rerun_or_collector_head_race_discards_narrow_route(self):
        for change in ({'run_attempt':2}, {'head_sha':'e'*40}, {'workflow_id':6}, {'head_branch':'other'}):
            api = API(5)
            def mutate(endpoint):
                if endpoint.endswith('/actions/runs/42') and api.calls.count(endpoint) == 2:
                    api.collector.update(change)
            api.mutate = mutate
            self.assertEqual({v['pullRequest'] for v in api.check()['checks']},set(range(7,12)))
            self.assertEqual(len(api.posts),5)

    def test_revoked_or_missing_review_still_blocks_the_target(self):
        for revoke in (lambda a:a.pulls[7].reviews.clear(),
                       lambda a:a.pulls[7].roles.update(maintainer='read'),
                       lambda a:a.pulls[7].members.clear()):
            api = API(5); revoke(api)
            result = api.check()
            self.assertEqual(result['checks'][0]['status'],'review-required')
            self.assertEqual(len(api.posts),1)
            self.assertEqual(api.posts[0][1]['conclusion'],'failure')

    def test_final_review_and_head_races_cannot_reuse_old_authority(self):
        api = API(5)
        def revoke(endpoint):
            if '/reviews?' in endpoint and api.calls.count(endpoint)==2:
                api.pulls[7].reviews.clear()
        api.mutate = revoke
        self.assertEqual(api.check()['checks'][0]['status'],'review-required')
        self.assertEqual(api.posts[0][1]['conclusion'],'failure')
        api = API(5)
        def move(endpoint):
            if endpoint.endswith('/pulls/7') and api.calls.count(endpoint)==4:
                api.pulls[7].pr['head']['sha']='e'*40
        api.mutate = move
        self.assertEqual(api.check()['checks'][0]['status'],'review-required')
        self.assertEqual(api.posts[0][1]['conclusion'],'failure')

    def test_second_operation_reads_every_route_and_authority_again(self):
        api = API(5)
        api.check(); first=list(api.calls)
        api.calls.clear(); api.check()
        self.assertEqual(api.calls, first)
        self.assertEqual(len(api.posts),2)


if __name__ == '__main__':
    unittest.main()
