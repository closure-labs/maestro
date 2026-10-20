#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release job eligibility against GitHub's inherited job-status semantics."""
import json
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
