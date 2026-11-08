#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release job eligibility against GitHub's inherited job-status semantics."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[4]


def jobs(filename):
    return json.loads(subprocess.check_output(
        ['yq', '-o=json', '.', str(ROOT / '.github/workflows' / filename)], text=True))['jobs']


CI, RELEASE = jobs('ci.yml'), jobs('release.yml')


def ancestors(graph, job):
    needs = graph[job].get('needs', [])
    if isinstance(needs, str):
        needs = [needs]
    return set(needs).union(*(ancestors(graph, parent) for parent in needs))


def without_cancelled_override(expression):
    # Remove the status conjunct wherever it appears, not an assumed prefix.
    terms = ' '.join(expression.split()).split(' && ')
    if terms.count('!cancelled()') != 1:
        raise ValueError('Expected exactly one explicit cancellation override')
    terms.remove('!cancelled()')
    result = ' && '.join(terms)
    if re.search(r'\b(?:always|cancelled|failure|success)\(\)', result):
        raise ValueError('Another status function would defeat the inherited-status mutation')
    return result


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
        'inputs.native_release_qualification_only': False,
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
    def assert_distribution_boundary(self, filename, name, job):
        # Classify every job. A new environment-bearing job must be reviewed,
        # never silently skipped by a job-name-only exemption.
        known = {
            'ci.yml': {'incoming_secret_scan', 'route', 'audit', 'equivalence', 'retained',
                       'appliance', 'installer', 'qualification', 'boot', 'security',
                       'signing', 'release_signal', 'verdict'},
            'release.yml': {'prepare', 'context', 'security', 'release', 'native_review',
                            'native_finalize', 'native_qualification_review', 'native_qualification'},
        }
        self.assertIn(filename, known)
        self.assertIn(name, known[filename], 'New jobs need an explicit distribution-boundary classification')
        self.assertNotIn('CACHIX_MAESTRO_AUTH_TOKEN', json.dumps(job))
        gated = {('release.yml', 'native_finalize'): 'native_review',
                 ('release.yml', 'native_qualification'): 'native_qualification_review'}
        if (filename, name) in gated:
            self.assertEqual(job.get('environment', {}).get('name'), 'findings-risk-review')
            self.assertEqual(job.get('needs'), gated[filename, name])
            self.assertNotIn('secrets.', json.dumps(job))
            permissions = {'actions': 'read', 'contents': 'write', 'attestations': 'write',
                           'artifact-metadata': 'write', 'id-token': 'write'}
            if name == 'native_qualification':
                permissions['contents'] = 'read'
                self.assertEqual(' '.join(job['if'].split()),
                    "inputs.native_release_qualification_only == true && needs.native_qualification_review.result == 'success' && "
                    "inputs.native_release != true && github.repository == 'closure-labs/maestro' && "
                    "github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch'")
                for forbidden in ('DECIDER', 'CACHIX', 'MAESTRO_NATIVE_RELEASE_ENABLED'):
                    self.assertNotIn(forbidden, json.dumps(job))
                self.assertNotIn('uses', job)
                prefix = "nix run --accept-flake-config .#devenv -- tasks run --mode single --option 'packages:pkgs!' '' "
                tasks = [step['run'] for step in job.get('steps', []) if 'run' in step]
                self.assertEqual(tasks, [prefix + 'release:native:stage-qualification', prefix + 'release:native:verify-qualification'])
                actions = [step for step in job.get('steps', []) if 'uses' in step]
                expected = [
                    ('step-security/harden-runner@dc2769abcc0fcfbadfc1df54081c1608579ef6b2', {'egress-policy'}),
                    ('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', {'ref', 'persist-credentials'}),
                    ('$/.github/actions/setup-nix', set()),
                    ('actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333', {'github-token', 'artifact-ids', 'run-id', 'path'}),
                    ('actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6', {'subject-path'}),
                    ('actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6', {'subject-path', 'sbom-path'}),
                    ('actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9', {'name', 'path', 'if-no-files-found', 'retention-days'}),
                ]
                self.assertEqual([(step['uses'], set(step.get('with', {}))) for step in actions], expected)
                self.assertIs(actions[1]['with']['persist-credentials'], False)
                self.assertEqual(actions[3]['with']['github-token'], '${{ github.token }}')
            self.assertEqual(job.get('permissions'), permissions)
        else:
            self.assertNotIn('environment', job)

    def test_candidate_builds_have_no_distribution_credentials(self):
        for filename in ['ci.yml', 'release.yml']:
            for name, job in jobs(filename).items():
                with self.subTest(filename=filename, job=name):
                    self.assert_distribution_boundary(filename, name, job)
        self.assertNotIn('publish', CI)
        self.assertNotIn('advance', RELEASE)

    def test_qualification_boundary_rejects_gate_permission_secret_and_writer_mutations(self):
        original = RELEASE['native_qualification']
        changes = [lambda j: j.pop('environment'),
                   lambda j: j['environment'].update(name='release'),
                   lambda j: j['permissions'].update(contents='write'),
                   lambda j: j['permissions'].update(actions='write'),
                   lambda j: j.update(needs='native_review'),
                   lambda j: j['env'].update(UNEXPECTED='${{ secrets.DECIDER_KEY }}'),
                   lambda j: j['env'].update(CACHIX_MAESTRO_AUTH_TOKEN='fixture'),
                   lambda j: j.update(**{'if': j['if'].replace('inputs.native_release_qualification_only == true', 'true')}),
                   lambda j: j.update(**{'if': j['if'] + ' || true'}),
                   lambda j: j['steps'].append({'run': 'release:native:publish'}),
                   lambda j: j['steps'].append({'uses': 'unexpected/action@main'}),
                   lambda j: j['steps'][1]['with'].update(token='${{ github.token }}'),
                   lambda j: j['steps'][1]['with'].update(**{'persist-credentials': True}),
                   lambda j: next(step for step in j['steps'] if 'run' in step).update(run='unexpected; ' + next(step['run'] for step in j['steps'] if 'run' in step))]
        for index, change in enumerate(changes):
            job = copy.deepcopy(original); change(job)
            with self.subTest(mutation=index), self.assertRaises(AssertionError):
                self.assert_distribution_boundary('release.yml', 'native_qualification', job)
        for filename, name in [('release.yml', 'unreviewed_gate'), ('ci.yml', 'native_qualification')]:
            with self.subTest(filename=filename, job=name), self.assertRaises(AssertionError):
                self.assert_distribution_boundary(filename, name, original)
        with self.assertRaises(AssertionError):
            self.assert_distribution_boundary('release.yml', 'unknown_ungated', {'steps': [], 'permissions': {'contents': 'write'}})
        for key in ('env', 'steps'):
            job = copy.deepcopy(CI['security'])
            if key == 'env':job.setdefault('env', {})['CACHIX_MAESTRO_AUTH_TOKEN'] = 'fixture'
            else:job.setdefault('steps', []).append({'env': {'CACHIX_MAESTRO_AUTH_TOKEN': 'fixture'}})
            with self.subTest(cache_scope=key), self.assertRaises(AssertionError):
                self.assert_distribution_boundary('ci.yml', 'security', job)

    def test_status_override_mutation_is_order_independent_and_fail_closed(self):
        states = dict.fromkeys(RELEASE, 'success') | {'prepare': 'skipped'}
        expression = without_cancelled_override(RELEASE['security']['if'])
        for source in ('!cancelled() && ' + expression, expression + ' && !cancelled()'):
            self.assertTrue(eligible(RELEASE, 'security', states, expression=source))
            mutated = without_cancelled_override(source)
            self.assertEqual(mutated, expression)
            self.assertIn('inputs.native_release_qualification_only != true', mutated)
            self.assertFalse(eligible(RELEASE, 'security', states, expression=mutated))
        for source in (expression, '!cancelled() && !cancelled() && ' + expression,
                       '!cancelled() && always() && ' + expression):
            with self.assertRaises(ValueError):without_cancelled_override(source)

    def test_publication_uses_separate_controller_and_same_fifo(self):
        for filename in ['publication.yml', 'release-publication.yml']:
            document = json.loads(subprocess.check_output(
                ['yq', '-o=json', '.', str(ROOT / '.github/workflows' / filename)], text=True))
            group=document['concurrency']['group']
            if filename=='publication.yml':
                rules=json.loads((ROOT/'modules/ci/checks/_lib/repository-rules.json').read_text())
                expected,=[row['needle'].removeprefix('group: ') for row in rules
                    if row.get('path')=='.github/workflows/publication.yml' and row.get('needle','').startswith('group: ')]
                self.assertEqual(group,expected)
                choices=re.fullmatch(r"\$\{\{ inputs.native_qualification_only && '([^']+)' \|\| '([^']+)' \}\}",group)
                self.assertIsNotNone(choices)
                self.assertEqual(choices[2],'maestro-publication')
                self.assertNotEqual(choices[1],choices[2])
            else:
                self.assertEqual(group,'maestro-publication')
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
            source=source.replace(' != true',' != True').replace(' == true',' == True')
            return eval(source.replace('&&', 'and').replace('||', 'or'), {'__builtins__': {}}, {})
        for event in ('workflow_dispatch', 'schedule', 'push'):
            for mode in ('default', '', 'disabled', 'enabled'):
                for configured in ('false', 'true'):
                    values = {'vars.MAESTRO_NATIVE_RELEASE_ENABLED':'false','inputs.native_release':False,
                              'github.repository': 'closure-labs/maestro', 'github.ref': 'refs/heads/main',
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
        result = subprocess.run(['bash', str(ROOT / 'modules/release/publication/_source/publication-inspect.sh')],
            env=dict(os.environ, PUBLICATION_DESTINATION='flakehub',
                     DECISION_PRODUCT='/does-not-exist', PUBLICATION_DESTINATIONS_SOURCE='/does-not-exist'),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Only cache publication inspection is supported', result.stderr)

    def test_serial_candidate_signal_survives_skipped_overlap_ancestor(self):
        states = dict.fromkeys(CI, 'success') | {'audit': 'skipped'}
        self.assertIn('audit', ancestors(CI, 'release_signal'))
        self.assertTrue(eligible(CI, 'release_signal', states))
        without_override = without_cancelled_override(CI['release_signal']['if'])
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
                without_override = without_cancelled_override(RELEASE[job]['if'])
                self.assertFalse(eligible(RELEASE, job, states, expression=without_override))
                self.assertFalse(eligible(RELEASE, job, states, cancelled=True))
                self.assertFalse(eligible(RELEASE, job, states, {'inputs.native_release_qualification_only': True}))
                for state in ['failure', 'cancelled', 'skipped', None]:
                    self.assertFalse(eligible(RELEASE, job, states | {'context': state}))
                for output in [{'needs.context.outputs.ready': 'false'},
                               {'needs.context.outputs.already_published': 'true'}]:
                    self.assertFalse(eligible(RELEASE, job, states, output))
        for state in ['failure', 'cancelled', 'skipped', None]:
            with self.subTest(scan=state):
                self.assertFalse(eligible(RELEASE, 'release', states | {'security': state}))


unittest.main()
