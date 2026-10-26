#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release job eligibility against GitHub's inherited job-status semantics."""
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


def jobs(filename):
    return json.loads(subprocess.check_output(
        ['yq', '-o=json', '.', str(ROOT / '.github/workflows' / filename)], text=True))['jobs']


CI, RELEASE = jobs('ci.yml'), jobs('release.yml')


def ancestors(graph, job):
    needs = graph[job].get('needs', [])
    if isinstance(needs, str):
        needs = [needs]
    return set(needs).union(*(ancestors(graph, parent) for parent in needs))


def eligible(graph, job, states, overrides=None, cancelled=False, expression=None):
    expression = ' '.join((expression or graph[job]['if']).split())
    # GitHub adds success() unless a status-check function is present. Include
    # transitive dependencies: a successful verdict does not erase skipped audit.
    if not re.search(r'\b(?:always|cancelled|failure|success)\(\)', expression):
        if any(states.get(parent) != 'success' for parent in ancestors(graph, job)):
            return False
    values = {
        'github.ref': 'refs/heads/main', 'github.event_name': 'workflow_dispatch',
        'inputs.release_candidate': True, 'inputs.release_request_id': '42',
        'vars.MAESTRO_RELEASE_CONTINUATION_ENABLED': 'true',
        'needs.context.outputs.ready': 'true', 'needs.context.outputs.already_published': 'false',
    }
    values.update({f'needs.{name}.result': state for name, state in states.items()})
    values.update(overrides or {})
    results = []
    for term in expression.split(' && '):
        if term == '!cancelled()':
            results.append(not cancelled)
            continue
        match = re.fullmatch(r"([\w.]+)\s*(==|!=)\s*('([^']*)'|true|false)", term)
        if not match:
            raise ValueError('Review eligibility contract for new expression: ' + term)
        key, operator, literal, quoted = match.groups()
        expected = quoted if literal.startswith("'") else literal == 'true'
        equal = values.get(key) == expected
        results.append(equal if operator == '==' else not equal)
    return all(results)


class ReleaseGraph(unittest.TestCase):
    def test_candidate_builds_have_no_distribution_credentials(self):
        for filename in ['ci.yml', 'release.yml']:
            for name, job in jobs(filename).items():
                if name == 'prepare':
                    continue
                for step in job.get('steps', []):
                    self.assertNotIn('CACHIX_MAESTRO_AUTH_TOKEN', step.get('env', {}))
                self.assertNotIn('environment', job)
        self.assertNotIn('publish', CI)
        self.assertNotIn('advance', RELEASE)

    def test_publication_uses_separate_controller_and_same_fifo(self):
        for filename in ['publication.yml', 'release-publication.yml']:
            document = json.loads(subprocess.check_output(
                ['yq', '-o=json', '.', str(ROOT / '.github/workflows' / filename)], text=True))
            self.assertEqual(document['concurrency']['group'], 'maestro-publication')
            self.assertEqual(document['concurrency']['queue'], 'max')
            steps = document['jobs']['publish']['steps']
            tasks = [step.get('run', '') for step in steps]
            self.assertTrue(any('ci:decision:handoff' in value for value in tasks))
            self.assertTrue(any('ci:distribution:restore' in value for value in tasks))
        publisher = jobs('release-publication.yml')['publish']
        self.assertEqual(publisher['environment'], 'release')
        self.assertTrue(any('release:journal' in step.get('run', '') for step in publisher['steps']))

    def test_transaction_trials_are_readonly_and_explicitly_selected(self):
        publisher = jobs('release-publication.yml')['publish']
        def expression(source, values):
            source = source.removeprefix('${{ ').removesuffix(' }}')
            for key in sorted(values, key=len, reverse=True):
                source = source.replace(key, repr(values[key]))
            return eval(source.replace('&&', 'and').replace('||', 'or'), {'__builtins__': {}}, {})
        for event in ('workflow_dispatch', 'schedule', 'push'):
            for mode in ('default', '', 'disabled', 'enabled'):
                for configured in ('false', 'true'):
                    values = {'github.repository': 'closure-labs/maestro', 'github.ref': 'refs/heads/main',
                              'github.event_name': event, 'inputs.transaction_trial': mode,
                              'inputs.candidate_run': '123', 'vars.MAESTRO_RELEASE_TRANSACTION_ENABLED': configured}
                    trial = event == 'workflow_dispatch' and mode in ('disabled', 'enabled')
                    verified = expression(publisher['env']['PUBLICATION_REQUIRE_VERIFIED'], values)
                    self.assertEqual(verified, 'true' if trial else 'false')
                    enabled = expression(publisher['env']['MAESTRO_RELEASE_TRANSACTION_ENABLED'], values)
                    self.assertEqual(enabled, ('true' if mode == 'enabled' else 'false') if trial else configured)
                    self.assertTrue(expression(publisher['if'], values))
                    values['inputs.candidate_run'] = ''
                    self.assertEqual(bool(expression(publisher['if'], values)), not trial)
                    values.update({'env.PUBLICATION_REQUIRE_VERIFIED': verified,
                                   'steps.cache.outputs.status': 'missing'})
                    for step in publisher['steps']:
                        command = step.get('run', '')
                        if command.endswith((' ci:distribution:restore', ' release:advance')):
                            self.assertEqual(bool(expression(step['if'], values)), not trial)
                        if 'create-github-app-token@' in step.get('uses', '') and step['with']['repositories'] != 'xo-nixpkg':
                            for permission in ('contents', 'pull-requests', 'actions'):
                                self.assertEqual(expression(step['with']['permission-' + permission], values),
                                                 'read' if trial else 'write')

    def test_publishers_have_no_flakehub_steps_or_oidc_permission(self):
        for filename in ('publication.yml', 'release-publication.yml'):
            publisher = jobs(filename)['publish']
            self.assertNotIn('id-token', publisher['permissions'])
            self.assertNotIn('flakehub', json.dumps(publisher).lower())
        policy = json.loads((ROOT / 'modules/ci/authority/_source/github/security-policy.json').read_text())
        self.assertNotIn('flakehub-push', json.dumps(policy))
        self.assertNotIn('flakehub-push@', (ROOT / 'modules/ci/checks/contracts.nix').read_text())
        result = subprocess.run(['bash', str(ROOT / 'modules/ci/authority/_source/publication-inspect.sh')],
            env=dict(os.environ, PUBLICATION_DESTINATION='flakehub',
                     DECISION_PRODUCT='/does-not-exist', PUBLICATION_DESTINATIONS_SOURCE='/does-not-exist'),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Only cache publication inspection is supported', result.stderr)

    def test_serial_candidate_signal_survives_skipped_overlap_ancestor(self):
        states = dict.fromkeys(CI, 'success') | {'audit': 'skipped'}
        self.assertIn('audit', ancestors(CI, 'release_signal'))
        self.assertTrue(eligible(CI, 'release_signal', states))
        without_override = ' '.join(CI['release_signal']['if'].split()).removeprefix('!cancelled() && ')
        self.assertFalse(eligible(CI, 'release_signal', states, expression=without_override))
        for state in ['failure', 'cancelled', 'skipped', None]:
            with self.subTest(verdict=state):
                self.assertFalse(eligible(CI, 'release_signal', states | {'verdict': state}))
        for key, value in [('github.ref', 'refs/heads/branch'), ('github.event_name', 'pull_request'),
                           ('inputs.release_candidate', False), ('inputs.release_request_id', ''),
                           ('vars.MAESTRO_RELEASE_CONTINUATION_ENABLED', 'false')]:
            with self.subTest(key=key):
                self.assertFalse(eligible(CI, 'release_signal', states, {key: value}))
        self.assertFalse(eligible(CI, 'release_signal', states, cancelled=True))

    def test_callback_scan_and_publication_survive_skipped_prepare(self):
        states = dict.fromkeys(RELEASE, 'success') | {'prepare': 'skipped'}
        for job in ['security', 'release']:
            with self.subTest(job=job):
                self.assertIn('prepare', ancestors(RELEASE, job))
                self.assertTrue(eligible(RELEASE, job, states))
                without_override = ' '.join(RELEASE[job]['if'].split()).removeprefix('!cancelled() && ')
                self.assertFalse(eligible(RELEASE, job, states, expression=without_override))
                self.assertFalse(eligible(RELEASE, job, states, cancelled=True))
                for state in ['failure', 'cancelled', 'skipped', None]:
                    self.assertFalse(eligible(RELEASE, job, states | {'context': state}))
                for output in [{'needs.context.outputs.ready': 'false'},
                               {'needs.context.outputs.already_published': 'true'}]:
                    self.assertFalse(eligible(RELEASE, job, states, output))
        for state in ['failure', 'cancelled', 'skipped', None]:
            with self.subTest(scan=state):
                self.assertFalse(eligible(RELEASE, 'release', states | {'security': state}))


unittest.main()
