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


class ReleaseGraph(unittest.TestCase):
    def assert_distribution_boundary(self, filename, name, job):
        # Classify every job. A new environment-bearing job must be reviewed,
        # never silently skipped by a job-name-only exemption.
        known = {
            'ci.yml': {'incoming_secret_scan', 'route', 'audit', 'equivalence', 'retained',
                       'appliance', 'installer', 'qualification', 'boot', 'security',
                       'signing', 'verdict'},
            'release.yml': {'native_review',
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

    def test_retired_controllers_and_ci_callback_are_absent(self):
        self.assertEqual(set(RELEASE), {'native_review','native_finalize','native_qualification_review','native_qualification'})
        self.assertNotIn('release_signal', CI)
        for filename in ('release-publication.yml','release-continuation.yml'):
            self.assertFalse((ROOT/'.github/workflows'/filename).exists())
        for filename in ('ci.yml','release.yml','publication.yml'):
            text=(ROOT/'.github/workflows'/filename).read_text()
            for command in ('release:signal','release:advance','release:pending','ci:decision:reconcile'):
                self.assertNotIn(command,text)

    def test_native_writers_share_fifo_but_trials_are_separate(self):
        publication=json.loads(subprocess.check_output(['yq','-o=json','.',str(ROOT/'.github/workflows/publication.yml')],text=True))
        self.assertEqual(set(publication['jobs']), {'native_review','native_publish','native_qualify'})
        self.assertNotIn('workflow_run',publication['on'])
        self.assertEqual(publication['concurrency'], {'group':"${{ inputs.native_qualification_only && 'maestro-publication-qualification' || 'maestro-publication' }}",'queue':'max','cancel-in-progress':False})
        self.assertEqual(RELEASE['native_finalize']['concurrency'], {'group':'maestro-publication','queue':'max','cancel-in-progress':False})
        for job in (publication['jobs']['native_publish'],RELEASE['native_finalize']):
            self.assertEqual(job['environment']['name'],'findings-risk-review')
            self.assertEqual(job['needs'],'native_review')
            self.assertNotIn('always()',job['if'])
            self.assertNotIn('!cancelled()',job['if'])
        self.assertEqual(publication['jobs']['native_qualify']['permissions']['contents'],'read')

    def test_flakehub_remains_unsupported(self):
        for filename in ('publication.yml','release.yml'):
            self.assertNotIn('flakehub', json.dumps(jobs(filename)).lower())
        policy = json.loads((ROOT / 'modules/ci/authority/_source/github/security-policy.json').read_text())
        self.assertNotIn('flakehub-push', json.dumps(policy))
        self.assertNotIn('flakehub-push@', (ROOT / 'modules/ci/checks/contracts.nix').read_text())
        result = subprocess.run(['bash', str(ROOT / 'modules/release/publication/_source/publication-inspect.sh')],
            env=dict(os.environ, PUBLICATION_DESTINATION='flakehub',
                     DECISION_PRODUCT='/does-not-exist', PUBLICATION_DESTINATIONS_SOURCE='/does-not-exist'),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Only cache publication inspection is supported', result.stderr)


unittest.main()
