#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Trusted CI approval must not grant merge authority or follow stale heads."""
from copy import deepcopy
import base64
import re
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
SOURCE = ROOT / ('modules/ci/authority/_source' if (ROOT / 'modules/ci/authority/_source').is_dir() else 'ci')
sys.path.insert(0, str(SOURCE / 'decisions'))
import ci_admission as admission

POLICY = json.loads((SOURCE / 'ci-admission-policy.json').read_text())
BOT = dict(POLICY['bot'], type='Bot')
DEPENDABOT = dict(POLICY['dependabot'], type='Bot')
TEMPLATES = {path: (ROOT / path).read_text() for path in POLICY['workflows']}
HUMAN = {'login': 'maintainer', 'id': 10, 'type': 'User'}
REPO = {'id': POLICY['repositoryId'], 'full_name': POLICY['repository']}
SHA = 'a' * 40


class API:
    def __init__(self):
        self.run = dict(id=42, run_attempt=1, event='pull_request', conclusion='action_required',
                        repository=REPO, head_repository={'id': 91}, head_branch='change', head_sha=SHA,
                        path='.github/workflows/ci.yml', workflow_id=5, actor=BOT, triggering_actor=BOT)
        self.pull = dict(number=7, state='open', draft=True, user=BOT,
                         base={'ref': 'main', 'repo': REPO},
                         head={'sha': SHA, 'ref': 'change', 'repo': {'id': 91}})
        self.calls, self.posts = [], []
        self.mutate = lambda endpoint: None
        self.member, self.permission = True, 'admin'
        self.workflow = {'path': self.run['path'], 'state': 'active'}
        self.candidate = None

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        self.mutate(endpoint)
        if endpoint.endswith('/actions/runs/42'):
            return deepcopy(self.run)
        if endpoint.endswith('/pulls/7'):
            return deepcopy(self.pull)
        if '/commits/' in endpoint:
            return [{'number': 7}]
        if '/contents/' in endpoint:
            path = self.run['path']
            raw = (self.candidate if self.candidate is not None else TEMPLATES[path]).encode()
            return {'type': 'file', 'path': path, 'size': len(raw), 'encoding': 'base64',
                    'content': base64.b64encode(raw).decode()}
        if '/actions/workflows/' in endpoint:
            return deepcopy(self.workflow)
        if endpoint.endswith('/teams/super-admins'):
            return {'id': 20196962, 'slug': 'super-admins', 'organization': {'login': 'closure-labs'}}
        if '/members?' in endpoint:
            return [HUMAN] if self.member else []
        if '/memberships/' in endpoint:
            return {'state': 'active' if self.member else 'pending', 'role': 'member'}
        if endpoint.endswith('/permission'):
            return {'role_name': self.permission}
        raise AssertionError(endpoint)

    def approve(self):
        return admission.approve_run(self, self.posts.append, POLICY, 42, TEMPLATES)

    def dependency(self):
        self.pull['user'] = DEPENDABOT
        self.pull['head']['repo'] = deepcopy(REPO)
        self.run.update(actor=DEPENDABOT, triggering_actor=DEPENDABOT, head_repository=deepcopy(REPO))

    def human(self):
        self.pull['user'] = HUMAN
        self.run.update(actor=HUMAN, triggering_actor=HUMAN)


class Admission(unittest.TestCase):
    def test_bot_draft_and_ready(self):
        for draft in (True, False):
            api = API(); api.pull['draft'] = draft
            self.assertEqual(api.approve(), 'approved')
            self.assertEqual(api.posts, [f'repos/{POLICY["repository"]}/actions/runs/42/approve'])

    def test_configured_dependency_families_and_all_workflows(self):
        ecosystems = re.findall(r'package-ecosystem: (\S+)', (ROOT / '.github/dependabot.yml').read_text())
        self.assertEqual(set(ecosystems), {'cargo', 'github-actions'})
        for ecosystem in ecosystems:
            for path in POLICY['workflows']:
                for draft in (True, False):
                    with self.subTest(ecosystem=ecosystem, path=path, draft=draft):
                        api = API(); api.dependency(); api.pull['draft'] = draft
                        api.run['path'] = api.workflow['path'] = path
                        # Branch names carry no authority. Cargo changes leave
                        # workflows alone; Actions changes update existing pins.
                        api.pull['head']['ref'] = api.run['head_branch'] = 'arbitrary-name'
                        if ecosystem == 'github-actions':
                            api.candidate = re.sub(r'@[0-9a-f]{40} # [^\n]+', '@' + 'b'*40 + ' # v99', TEMPLATES[path])
                        self.assertEqual(api.approve(), 'approved')
                        self.assertEqual(api.posts, [f'repos/{POLICY["repository"]}/actions/runs/42/approve'])
                        self.assertFalse(any('/reviews' in call or '/merge' in call for call in api.posts))

    def test_dependabot_identity_repository_and_actors(self):
        for field in ('user', 'actor', 'triggering_actor'):
            for change in ({'id': 1}, {'type': 'User'}, {'login': 'other[bot]'}):
                api = API(); api.dependency()
                target = api.pull if field == 'user' else api.run
                target[field] = dict(DEPENDABOT, **change)
                try:
                    self.assertNotEqual(api.approve(), 'approved')
                except admission.AuthorityError:
                    pass
                self.assertFalse(api.posts)
        for repo in ({'id': 91, 'full_name': 'other/fork'}, dict(REPO, full_name='other/name')):
            api = API(); api.dependency()
            api.pull['head']['repo'] = api.run['head_repository'] = repo
            self.assertEqual(api.approve(), 'unsafe-dependency-workflow'); self.assertFalse(api.posts)
        api = API(); api.pull['head']['ref'] = api.run['head_branch'] = 'dependabot/cargo/update'
        api.pull['user'] = dict(BOT, id=1)
        self.assertNotEqual(api.approve(), 'approved'); self.assertFalse(api.posts)

    def test_dependency_workflow_cannot_change_privilege_or_commands(self):
        original = TEMPLATES['.github/workflows/ci.yml']
        mutations = [
            original.replace('contents: read', 'contents: write', 1),
            original.replace("github.ref == 'refs/heads/main'", 'true'),
            original.replace('ci:route', 'ci:publish'),
            original.replace('actions/checkout@', 'evil/checkout@'),
            original.replace('pull_request:', 'pull_request_target:', 1),
            original.replace('persist-credentials: false', 'persist-credentials: true'),
            original.replace('uses: $/.github/actions/setup-nix', 'uses: ./evil'),
            original + '\n  malicious:\n    uses: evil/reusable@main\n',
            original.replace('permission-contents: read', 'permission-contents: write'),
            original.replace('run: nix run', 'run: echo ${{ secrets.DECIDER_KEY }}; nix run', 1),
        ]
        for candidate in mutations:
            api = API(); api.dependency(); api.candidate = candidate
            self.assertEqual(api.approve(), 'unsafe-dependency-workflow'); self.assertFalse(api.posts)
        api = API(); api.dependency()
        self.assertEqual(admission.approve_run(api, api.posts.append, POLICY, 42), 'unsafe-dependency-workflow')
        self.assertFalse(api.posts)

    def test_dependency_head_and_run_races(self):
        for target in ('pull', 'run'):
            api = API(); api.dependency()
            def mutate(endpoint):
                if target == 'pull' and endpoint.endswith('/pulls/7') and api.calls.count(endpoint) == 2:
                    api.pull['head']['sha'] = 'c'*40
                if target == 'run' and endpoint.endswith('/actions/runs/42') and api.calls.count(endpoint) == 2:
                    api.run['triggering_actor'] = dict(DEPENDABOT, id=1)
            api.mutate = mutate
            self.assertEqual(api.approve(), 'binding-changed'); self.assertFalse(api.posts)

    def test_dependency_workflow_metadata_fails_closed(self):
        for change in ({'type': 'symlink'}, {'encoding': 'none'}, {'size': 131073},
                       {'content': 'invalid base64!'}, {'path': 'other'}, {'size': 1}):
            api = API(); api.dependency()
            def read(endpoint):
                response = api(endpoint)
                if '/contents/' in endpoint:
                    response.update(change)
                return response
            self.assertEqual(admission.approve_run(read, api.posts.append, POLICY, 42, TEMPLATES),
                             'unsafe-dependency-workflow')
            self.assertFalse(api.posts)

    def test_pr_privilege_boundaries(self):
        def jobs(path):
            text = (ROOT / path).read_text()
            return {match[0]: match[1] for match in re.findall(
                r'(?ms)^  ([a-z_]+):\n(.*?)(?=^  [a-z_]+:|\Z)', text.split('jobs:\n', 1)[1])}
        protected = "github.ref == 'refs/heads/main'"
        events = "contains(fromJSON('[\"push\",\"schedule\",\"workflow_dispatch\"]'), github.event_name)"
        ci = jobs('.github/workflows/ci.yml')
        self.assertEqual(TEMPLATES['.github/workflows/ci.yml'].count('secrets.'), 1)
        self.assertNotIn('secrets.', TEMPLATES['.github/workflows/codeql.yml'])
        self.assertNotIn('secrets.', TEMPLATES['.github/workflows/decision-events.yml'])
        for path in POLICY['workflows']:
            for name, body in jobs(path).items():
                header = body.split('    steps:', 1)[0]
                if re.search(r'^      [a-z-]+: write$', header, re.M):
                    condition = header.split('    if:', 1)[1].split('    runs-on:', 1)[0]
                    self.assertIn(protected, condition, (path, name))
                    # release_signal is an explicitly internal main dispatch.
                    self.assertTrue(events in condition or "github.event_name == 'workflow_dispatch'" in condition)
        self.assertNotIn('write', ci['security'].split('    outputs:', 1)[0])
        self.assertNotIn('actions/attest@', ci['security'])
        self.assertIn('Attest native evidence', ci['signing'])
        mint = ci['retained'].split('      - name: Mint protected-main', 1)[1].split('        id:', 1)[0]
        self.assertNotIn('pull_request', mint)
        self.assertIn(protected, mint)
        self.assertIn("github.event_name == 'push'", mint)
        codeql = jobs('.github/workflows/codeql.yml')
        self.assertIn('upload: never', codeql['analyze'])
        self.assertIn('upload-database: false', codeql['analyze'])
        self.assertNotIn('write', codeql['analyze'].split('    strategy:', 1)[0])
        self.assertIn('upload-sarif@', codeql['publish'])

    def test_super_admin_draft_and_ready(self):
        for draft in (True, False):
            api = API(); api.human(); api.pull['draft'] = draft
            self.assertEqual(api.approve(), 'approved')
            self.assertGreaterEqual(sum('/memberships/' in call for call in api.calls), 2)

    def test_impostor_bot_and_untrusted_author(self):
        for user in (dict(BOT, id=1), dict(BOT, type='User'), dict(HUMAN, id=11)):
            api = API(); api.pull['user'] = user
            try:
                self.assertNotEqual(api.approve(), 'approved')
            except admission.AuthorityError:
                pass
            self.assertFalse(api.posts)

    def test_untrusted_pusher_or_rerunner(self):
        for field in ('actor', 'triggering_actor'):
            api = API(); api.run[field] = dict(BOT, id=1)
            self.assertNotEqual(api.approve(), 'approved'); self.assertFalse(api.posts)

    def test_revoked_membership_or_repository_permissions(self):
        for field, value in [('member', False), ('permission', 'write'), ('permission', 'read')]:
            api = API(); api.human(); setattr(api, field, value)
            self.assertNotEqual(api.approve(), 'approved'); self.assertFalse(api.posts)

    def test_revocation_during_checks(self):
        api = API(); api.human()
        def mutate(endpoint):
            if sum('/members?' in call for call in api.calls) >= 4:
                api.member = False
        api.mutate = mutate
        self.assertEqual(api.approve(), 'identity-revoked'); self.assertFalse(api.posts)

    def test_wrong_run_event_repository_workflow_or_status(self):
        for field, value in [('event','push'), ('repository', {'id': 3}),
                             ('path','.github/workflows/publish.yml'), ('conclusion','success'),
                             ('head_sha','not-a-sha')]:
            api = API(); api.run[field] = value
            self.assertNotEqual(api.approve(), 'approved'); self.assertFalse(api.posts)

    def test_workflow_identity_mismatch(self):
        api = API(); api.workflow['path'] = '.github/workflows/publish.yml'
        self.assertEqual(api.approve(), 'workflow-mismatch'); self.assertFalse(api.posts)

    def test_closed_stale_foreign_or_non_main_pr(self):
        for change in ('closed','sha','repo','base','branch'):
            api = API()
            if change == 'closed': api.pull['state'] = 'closed'
            if change == 'sha': api.pull['head']['sha'] = 'b'*40
            if change == 'repo': api.pull['head']['repo']['id'] = 92
            if change == 'base': api.pull['base']['ref'] = 'other'
            if change == 'branch': api.pull['head']['ref'] = 'other'
            self.assertNotEqual(api.approve(), 'approved'); self.assertFalse(api.posts)

    def test_head_changes_before_mutation(self):
        api = API()
        def mutate(endpoint):
            if endpoint.endswith('/pulls/7') and api.calls.count(endpoint) == 2:
                api.pull['head']['sha'] = 'b'*40
        api.mutate = mutate
        self.assertEqual(api.approve(), 'binding-changed'); self.assertFalse(api.posts)

    def test_run_attempt_changes_before_mutation(self):
        api = API()
        def mutate(endpoint):
            if endpoint.endswith('/actions/runs/42') and api.calls.count(endpoint) == 2:
                api.run['run_attempt'] = 2
        api.mutate = mutate
        self.assertEqual(api.approve(), 'binding-changed'); self.assertFalse(api.posts)

    def test_api_failure_never_approves(self):
        api = API()
        def fail(endpoint): raise admission.AuthorityError('Unavailable')
        api.mutate = fail
        with self.assertRaises(admission.AuthorityError): api.approve()
        self.assertFalse(api.posts)

    def test_ambiguous_post_not_retried(self):
        api = API(); calls = []
        def fail(endpoint):
            calls.append(endpoint)
            raise TimeoutError('Lost acknowledgement')
        with self.assertRaises(TimeoutError): admission.approve_run(api, fail, POLICY, 42)
        self.assertEqual(len(calls), 1)

    def test_pagination_is_complete_and_bounded(self):
        calls = []
        def api(endpoint):
            calls.append(endpoint)
            return {'workflow_runs': [{'id': i} for i in range(100)] if len(calls)==1 else [{'id': 200}]}
        self.assertEqual(len(admission.pending_runs(api, POLICY)), 101)
        with self.assertRaises(admission.AuthorityError):
            admission.pending_runs(lambda _: {'workflow_runs':[{'id':i} for i in range(100)]}, POLICY)

    def test_workflow_executes_only_protected_controller(self):
        workflow = (ROOT/'.github/workflows/ci-admission.yml').read_text()
        self.assertIn('ref: main', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('ci:admit-trusted', workflow)
        self.assertIn("cron: '*/15 * * * *'", workflow)
        for forbidden in ('head.sha', 'pull_request_target:', 'permission-contents: write',
                          'permission-pull-requests: write', 'permission-checks: write', 'download-artifact'):
            self.assertNotIn(forbidden, workflow)


if __name__ == '__main__':
    unittest.main()
