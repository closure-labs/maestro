#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Decision-only eligibility, authenticated identities and conservative verdicts."""
from contextlib import redirect_stdout
from copy import deepcopy
import base64
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'nix/automation/decisions'))
import decision_only as reuse


class Eligibility(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.command('init', '-q')
        (self.root / 'README.md').write_text('base')
        self.command('add', '.')
        self.command('commit', '-qm', 'base')
        self.base = self.command('rev-parse', 'HEAD')
        self.proposal = {'schema': 1, 'kind': 'security-findings', 'payload': {'packet': {
            'reference': 'ghcr.io/closure-labs/maestro-decisions@sha256:' + 'a' * 64,
            'sha256': 'b' * 64, 'producer': {'runId': 10}}, 'disposition': 'accepted'}}
        self.path = reuse.authority.proposal_path(self.proposal)
        file = self.root / self.path
        file.parent.mkdir(parents=True)
        file.write_text(json.dumps(self.proposal, sort_keys=True, indent=2) + '\n')

    def command(self, *arguments):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Fixture',
                                        '-c', 'user.email=fixture@example.invalid', '-C', str(self.root), *arguments], text=True).strip()

    def commit(self):
        self.command('add', '.')
        self.command('commit', '-qm', 'candidate')
        return self.command('rev-parse', 'HEAD')

    def test_exact_regular_canonical_addition_is_the_only_candidate(self):
        source = self.commit()
        descriptor = reuse.inspect(self.root, self.base, source)
        self.assertEqual(descriptor['decisionPath'], self.path)
        self.assertEqual(descriptor['decisionHash'], reuse.common.canonical_hash(self.proposal))
        self.assertIsNone(descriptor['productHash'])

    def test_source_must_match_actual_checkout(self):
        self.commit()
        with self.assertRaisesRegex(ValueError, 'checkout differs from immutable source'):
            reuse.inspect(self.root, self.base, self.base)

    def test_mixed_changes_mode_changes_and_symlinks_use_normal_validation(self):
        (self.root / 'README.md').write_text('changed')
        self.assertIsNone(reuse.inspect(self.root, self.base, self.commit()))
        self.command('reset', '--hard', self.base)
        path = self.root / self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.proposal, sort_keys=True, indent=2) + '\n')
        path.chmod(0o755)
        self.assertIsNone(reuse.inspect(self.root, self.base, self.commit()))
        self.command('reset', '--hard', self.base)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to('../../../README.md')
        self.assertIsNone(reuse.inspect(self.root, self.base, self.commit()))

    def test_modifications_deletions_and_renames_are_not_additions(self):
        source = self.commit()
        (self.root / self.path).write_text('{}')
        self.assertIsNone(reuse.inspect(self.root, source, self.commit()))
        self.command('reset', '--hard', source)
        (self.root / self.path).rename(self.root / (self.path + '.renamed'))
        self.assertIsNone(reuse.inspect(self.root, source, self.commit()))
        self.command('reset', '--hard', source)
        (self.root / self.path).unlink()
        self.assertIsNone(reuse.inspect(self.root, source, self.commit()))

    def test_content_hash_and_canonical_native_encoding_are_required(self):
        (self.root / self.path).write_text(json.dumps(self.proposal))
        with self.assertRaises(ValueError):
            reuse.inspect(self.root, self.base, self.commit())


class RetainedEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'source'
        self.root.mkdir()
        self.directory = Path(self.temporary.name) / 'retained'
        self.cfg = {'schema': 1, 'repository': 'closure-labs/maestro', 'profiles': ['maestro'],
                    'maxEvidenceAgeHours': 24, 'maxDatabaseAgeHours': 48}
        self.producer = {'workflow': '.github/workflows/ci.yml', 'signerWorkflow': '.github/workflows/ci.yml',
                         'runId': 100, 'runAttempt': 2, 'revision': 'a' * 40}
        self.product = {'schema': 1, 'repository': self.cfg['repository'], 'revision': 'a' * 40,
                        'products': {'maestro': {'storePath': '/nix/store/' + 'a' * 32 + '-fixture',
                                                 'narHash': 'sha256-' + 'A' * 43 + '='}}, 'roots': {}, 'assets': {}}
        self.product_hash = reuse.common.canonical_hash(self.product)
        now = dt.datetime.now(dt.timezone.utc)
        inventory = b'{}\n'
        hashes = ''.join(hashlib.sha256(inventory).hexdigest() + '  inventory/' + name + '\n'
                         for name in ('maestro-system.cdx.json', 'xen-orchestra-supply.cdx.json', 'Cargo.lock')).encode()
        native = {'status': 'complete', 'scannerHealth': 'healthy', 'scannedAt': now.isoformat(),
                  'database': {'valid': True, 'built': now.isoformat()},
                  'evidence': {'inventory': {'sha256': hashlib.sha256(inventory).hexdigest(), 'size': len(inventory)},
                               'inputHashes': {'sha256': hashlib.sha256(hashes).hexdigest(), 'size': len(hashes)}}}
        self.scans = {'schema': 1, 'repository': self.cfg['repository'], 'revision': 'a' * 40,
                      'producer': self.producer, 'productProducer': self.producer,
                      'scannedAt': now.isoformat(), 'expiresAt': (now + dt.timedelta(hours=24)).isoformat(),
                      'profiles': {'maestro': native}}
        self.files = {'product.json': json.dumps(self.product).encode(), 'scans.json': json.dumps(self.scans).encode(),
                      'inputs.sha256': hashes, **{'inventory/' + name: inventory for name in
                      ('maestro-system.cdx.json', 'xen-orchestra-supply.cdx.json', 'Cargo.lock')}}
        self.descriptor = {'schema': 1, 'base': 'b' * 40, 'source': 'c' * 40, 'decisionPath': 'fixture',
                           'decisionHash': 'd' * 64, 'productHash': None, 'packet': {
                               'reference': 'ghcr.io/closure-labs/maestro-decisions@sha256:' + 'a' * 64, 'sha256': 'e' * 64,
                               'producer': dict(self.producer, repository=self.cfg['repository'], sourceRevision='a' * 40)}}
        self.inputs = {'media_input': '1' * 64, 'evidence_input': '2' * 64}
        self.proposal = {'schema': 1, 'kind': 'security-findings', 'payload': {
            'packet': self.descriptor['packet'], 'profiles': {'maestro': []}, 'disposition': 'accepted',
            'rationale': 'Fixture retained native findings', 'supersedes': []}}
        self.patch(patch.dict(os.environ, {'MAESTRO_DECISION_RETAINED_SOURCE': str(ROOT / 'nix/automation/decision-retained.py')}))
        self.patch(patch.object(reuse, 'inspect', return_value=self.descriptor))
        self.patch(patch.object(reuse, 'git', return_value=b''))
        self.patch(patch.object(reuse, 'source_proposal', return_value=self.proposal))
        self.patch(patch.object(reuse, 'normalize_findings', return_value=[]))
        self.patch(patch.object(reuse.packets, 'metadata_bytes', side_effect=lambda ref, digest, name, **kw: self.files[name]))
        self.patch(patch.object(reuse.common, 'scans', return_value=self.scans))
        self.patch(patch.object(reuse.common, 'product', return_value=self.product))
        self.producer_check = self.patch(patch.object(reuse.common, 'verify_producer'))
        self.state = self.patch(patch.object(reuse, 'qualification_state', return_value=dict(self.inputs, source_commit='a' * 40)))
        self.evaluated = self.patch(patch.object(reuse, 'evaluated_inputs', return_value=self.inputs))
        self.generator_inputs = {name: '/nix/store/' + 'a' * 32 + '-' + name for name in reuse.GENERATOR_PACKAGES}
        self.packages = self.patch(patch.object(reuse, 'evaluated_generators', return_value=self.generator_inputs))
        self.patch(patch.object(reuse.common, 'ledger', return_value=('f' * 40, {})))
        self.release = self.patch(patch.object(reuse.common, 'active_release', return_value=('3' * 64, {'payload': {'disposition': 'accepted'}})))
        self.gate = self.patch(patch.object(reuse.common, 'gate', return_value={'productHash': self.product_hash, 'decisionHash': '4' * 64}))
        for name in reuse.GENERATORS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'original generator\n')
        self.patch(patch.object(reuse.authority, 'github_api', side_effect=self.generator))

    def patch(self, value):
        self.addCleanup(value.stop)
        return value.start()

    def generator(self, endpoint):
        raw = b'original generator\n'
        sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        return {'encoding': 'base64', 'content': base64.b64encode(raw).decode(), 'sha': sha, 'size': len(raw)}

    def test_unchanged_inputs_retain_exact_original_producer_and_evidence_identities(self):
        result = reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.assertTrue(result['eligible'])
        self.assertEqual(result['producer'], self.producer)
        self.assertEqual(result['productProducer'], self.producer)
        self.assertEqual(result['inputs'], self.inputs)
        self.assertEqual(result['generatorInputs'], self.generator_inputs)
        self.assertEqual(result['productHash'], self.product_hash)
        self.assertNotEqual(result['productDecisionHash'], result['securityDecisionHash'])
        self.gate.assert_called_once()

    def test_changed_actual_inputs_or_generator_requires_full_validation(self):
        self.evaluated.return_value = dict(self.inputs, media_input='5' * 64)
        with self.assertRaises(reuse.UnavailableEvidence):
            reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_not_called()

    def test_changed_actual_generator_dependency_requires_full_validation(self):
        changed = dict(self.generator_inputs, **{reuse.GENERATOR_PACKAGES[0]: '/nix/store/' + 'b' * 32 + '-changed-tool'})
        self.packages.side_effect = [self.generator_inputs, changed]
        with self.assertRaises(reuse.UnavailableEvidence):
            reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_not_called()

    def test_refreshed_ci_evidence_preserves_the_older_product_producer(self):
        evidence = dict(self.producer, runId=101, revision='e' * 40)
        self.scans['producer'] = evidence
        self.files['scans.json'] = json.dumps(self.scans).encode()
        self.descriptor['packet']['producer'] = dict(evidence, repository=self.cfg['repository'], sourceRevision='a' * 40)
        self.state.return_value = dict(self.inputs, source_commit=evidence['revision'])
        result = reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.assertEqual(result['producer'], evidence)
        self.assertEqual(result['productProducer'], self.producer)
        self.assertEqual(self.state.call_args.args[1], evidence)
        self.producer_check.assert_any_call(self.cfg, evidence, self.scans['revision'], require_main=True)

    def test_every_scanner_and_inventory_generator_must_match(self):
        for index, name in enumerate(reuse.GENERATORS):
            with self.subTest(generator=name):
                path = self.root / name
                path.write_bytes(b'changed generator\n')
                with self.assertRaises(reuse.UnavailableEvidence):
                    reuse.verify(self.cfg, self.root, self.descriptor, self.directory.with_name('evidence-' + str(index)))
                path.write_bytes(b'original generator\n')
        self.gate.assert_not_called()

    def test_unavailable_retained_transport_or_generator_uses_full_validation(self):
        failure = subprocess.CalledProcessError(1, ['unavailable-transport'])
        for index, (module, name) in enumerate(((reuse.packets, 'metadata_bytes'), (reuse.authority, 'github_api'))):
            with self.subTest(transport=name), patch.object(module, name, side_effect=failure):
                with self.assertRaises(reuse.UnavailableEvidence):
                    reuse.verify(self.cfg, self.root, self.descriptor, self.directory.with_name('unavailable-' + str(index)))
        self.gate.assert_not_called()

    def test_registry_absence_and_transport_are_distinct_from_integrity_conflicts(self):
        for raw in (b'HTTP/1.1 404 Not Found', b'manifest_unknown', b'connection refused', b'HTTP/1.1 503 Unavailable'):
            with self.subTest(stderr=raw):
                error = reuse.packets.command_failure(['oras', 'manifest', 'fetch'], 1, raw, len(raw), 1024)
                self.assertIsInstance(error, reuse.packets.RegistryUnavailable)
        for raw in (b'HTTP/1.1 409 Conflict', b'digest_invalid', b'manifest_invalid', b'HTTP/1.1 409 connection refused'):
            with self.subTest(stderr=raw):
                error = reuse.packets.command_failure(['oras', 'manifest', 'fetch'], 1, raw, len(raw), 1024)
                self.assertIsInstance(error, ValueError)
                self.assertNotIsInstance(error, reuse.packets.RegistryUnavailable)

    def test_dirty_or_untracked_inputs_cannot_authorize_reuse(self):
        with patch.object(reuse, 'git', return_value=b'mutated local input'), self.assertRaises(ValueError):
            reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_not_called()

    def test_changed_generator_is_not_excluded_to_manufacture_a_match(self):
        (self.root / reuse.GENERATORS[0]).write_text('changed generator')
        with self.assertRaises(reuse.UnavailableEvidence):
            reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_not_called()

    def test_unmerged_product_acceptance_cannot_supply_authority(self):
        self.release.return_value = (None, None)
        with self.assertRaises(reuse.UnavailableEvidence):
            reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_not_called()

    def test_revoked_review_and_inventory_integrity_fail_closed(self):
        self.gate.side_effect = reuse.authority.HumanDecisionRequired('review revoked')
        with self.assertRaises(reuse.authority.HumanDecisionRequired):
            reuse.verify(self.cfg, self.root, self.descriptor, self.directory)

    def test_mutated_retained_inventory_cannot_be_reused(self):
        self.files['inventory/maestro-system.cdx.json'] = b'mutated'
        with self.assertRaises(ValueError):
            reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_not_called()

    def test_native_proposal_payload_must_match_retained_findings_and_validation(self):
        self.proposal['payload']['profiles'] = {'maestro': [{'untrusted': 'finding'}]}
        with self.assertRaises(ValueError):
            reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_not_called()

    def test_expired_evidence_requires_full_validation(self):
        with patch.object(reuse.scheduling, 'observation_expiry', return_value=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)):
            with self.assertRaises(reuse.UnavailableEvidence):
                reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_not_called()

    def test_late_expiry_cannot_become_successful_reuse(self):
        now = dt.datetime.now(dt.timezone.utc)
        clock = SimpleNamespace(datetime=Mock(now=Mock(side_effect=[now, now + dt.timedelta(seconds=2)])), timezone=dt.timezone)
        with patch.object(reuse.scheduling, 'observation_expiry', return_value=now + dt.timedelta(seconds=1)), patch.object(reuse, 'dt', clock):
            with self.assertRaises(reuse.UnavailableEvidence):
                reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_called_once()

    def test_current_authority_and_original_attestation_are_not_optional(self):
        self.producer_check.side_effect = ValueError('original producer is untrusted')
        with self.assertRaises(ValueError):
            reuse.verify(self.cfg, self.root, self.descriptor, self.directory)
        self.gate.assert_not_called()


class Verdict(unittest.TestCase):
    def test_only_successful_matching_v4_verification_can_skip_native_operations(self):
        descriptor = {'schema': 1, 'decisionHash': 'a' * 64}
        plan = {'schema_version': 4, 'publish_required': False, 'retained_evidence': descriptor,
                'qualification': {'required': True, 'mode': 'qualify-media', 'artifact_run_id': 1, 'media_run_id': 1,
                                  'evidence_run_id': 1, 'media_input': 'b' * 64, 'evidence_input': 'c' * 64}}
        environment = dict(os.environ, CI_PLAN=json.dumps(plan), ROUTE_RESULT='success', AUDIT_OVERLAP='false',
                           AUDIT_RESULT='skipped', QUALIFICATION_RESULT='skipped', SECURITY_RESULT='skipped',
                           SIGNING_RESULT='skipped', RETAINED_RESULT='success', RETAINED_REUSE='true',
                           RETAINED_DESCRIPTOR_HASH=reuse.common.canonical_hash(descriptor), MAESTRO_DECISION_ONLY_REUSE_ENABLED='true')
        command = ['bash', str(ROOT / 'nix/automation/verdict.sh')]
        self.assertEqual(subprocess.run(command, env=environment).returncode, 0)
        for field, value in (('RETAINED_RESULT', 'failure'), ('RETAINED_DESCRIPTOR_HASH', 'f' * 64),
                             ('MAESTRO_DECISION_ONLY_REUSE_ENABLED', 'false'), ('SECURITY_RESULT', 'success')):
            with self.subTest(field=field):
                self.assertNotEqual(subprocess.run(command, env=dict(environment, **{field: value}), capture_output=True).returncode, 0)
        legacy = dict(plan, schema_version=3)
        del legacy['retained_evidence']
        self.assertNotEqual(subprocess.run(command, env=dict(environment, CI_PLAN=json.dumps(legacy)), capture_output=True).returncode, 0)


class Evaluation(unittest.TestCase):
    def test_authority_reader_is_read_only_and_uses_protected_controller_for_pr_and_queue(self):
        workflow = json.loads(subprocess.check_output(['yq', '-o=json', '.', str(ROOT / '.github/workflows/ci.yml')], text=True))
        job = workflow['jobs']['retained']
        self.assertIn("github.event.pull_request.base.ref == 'main'", job['if'])
        setup = next(step for step in job['steps'] if step.get('name') == 'Set up Nix')
        self.assertEqual(setup['uses'], './controller/.github/actions/setup-nix')
        checkout = next(step for step in job['steps'] if step.get('with', {}).get('path') == 'controller')
        self.assertTrue(checkout['uses'].startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'], '${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.sha }}')
        self.assertFalse(checkout['with']['persist-credentials'])
        mint = next(step for step in job['steps'] if step.get('id') == 'authority')
        condition = mint['if']
        self.assertIn("hashFiles('controller/.github/workflows/ci.yml') == hashFiles('candidate/.github/workflows/ci.yml')", condition)
        self.assertIn('github.event.pull_request.head.repo.full_name == github.repository', condition)
        self.assertIn("github.event_name == 'merge_group'", condition)
        self.assertTrue(all(value == 'read' for key, value in mint['with'].items() if key.startswith('permission-')))
        self.assertTrue(all(value == 'read' for value in job['permissions'].values()))
        verify = next(step for step in job['steps'] if step.get('id') == 'verify')
        self.assertEqual(verify['working-directory'], 'controller')
        self.assertEqual(verify['env']['CI_CANDIDATE_ROOT'], '${{ github.workspace }}/candidate')
        self.assertNotIn('secrets', verify['run'])

    def test_generator_evaluation_uses_complete_native_packages_and_sanitized_environment(self):
        expected = {name: '/nix/store/' + 'a' * 32 + '-' + name for name in reuse.GENERATOR_PACKAGES}
        with patch.dict(os.environ, {'GH_TOKEN': 'private-reader', 'REGISTRY_TOKEN': 'private-registry'}), \
             patch.object(reuse.operations, 'run', return_value=SimpleNamespace(stdout=json.dumps(expected))) as evaluate:
            self.assertEqual(reuse.evaluated_generators('github:closure-labs/maestro/' + 'a' * 40), expected)
            args = evaluate.call_args.args[0]
            self.assertIn('github:closure-labs/maestro/' + 'a' * 40 + '#packages.x86_64-linux', args)
            for name in reuse.GENERATOR_PACKAGES:
                self.assertIn('p."' + name + '".outPath;', args[-1])
            self.assertFalse({'GH_TOKEN', 'REGISTRY_TOKEN'} & evaluate.call_args.kwargs['env'].keys())
            self.assertIn('allow-import-from-derivation', args)

    def test_unavailable_evidence_requests_full_validation_without_reuse(self):
        for flag in ('false', 'true'):
            for failure in (reuse.UnavailableEvidence('expired pointer'), reuse.packets.RegistryUnavailable('missing registry object')):
                with self.subTest(flag=flag, error=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / 'proof.json'
                    arguments = ['decision_only.py', '--config', 'unused', '--output', str(output), 'verify']
                    environment = {'CI_PLAN': json.dumps({'retained_evidence': {'source': 'a' * 40}}),
                                   'GITHUB_ACTOR': 'fixture', 'MAESTRO_DECISION_ONLY_REUSE_ENABLED': flag}
                    with patch.dict(os.environ, environment), patch.object(sys, 'argv', arguments), \
                         patch.object(reuse.common, 'config', return_value={}), \
                         patch.object(reuse.operations, 'run', return_value=SimpleNamespace(returncode=0)), \
                         patch.object(reuse, 'verify', side_effect=failure), redirect_stdout(io.StringIO()):
                        self.assertIsNone(reuse.main())
                    result = json.loads(output.read_text())
                    self.assertEqual(result['status'], 'full-validation-required')
                    self.assertFalse(result['eligible'])
                    self.assertFalse(result['reused'])

    def test_actual_evaluation_has_no_credentials_or_input_exclusions(self):
        graph = {'media': {'iso': 'original', 'newInput': 'first'}, 'evidence': {'generator': 'original'}}
        def isolated(*args, **kwargs):
            environment = kwargs['env']
            self.assertEqual((Path(environment['NIX_CONF_DIR']) / 'nix.conf').read_text(), '')
            self.assertEqual(environment['NIX_USER_CONF_FILES'], '/dev/null')
            self.assertEqual(environment['GIT_CONFIG_GLOBAL'], '/dev/null')
            self.assertEqual(environment['GIT_CONFIG_NOSYSTEM'], '1')
            self.assertEqual(environment['GIT_TERMINAL_PROMPT'], '0')
            return SimpleNamespace(stdout=json.dumps(graph))
        with patch.dict(os.environ, {'GH_TOKEN': 'private-reader', 'REGISTRY_TOKEN': 'private-registry',
                                   'NIX_CONF_DIR': '/private-configuration', 'NIX_CONFIG': 'private-setting'}), \
             patch.object(reuse.operations, 'run', side_effect=isolated) as evaluate:
            first = reuse.evaluated_inputs(ROOT)
            environment = evaluate.call_args.kwargs['env']
            self.assertFalse({'GH_TOKEN', 'REGISTRY_TOKEN'} & environment.keys())
            self.assertNotIn('private-setting', environment['NIX_CONFIG'])
            self.assertIn('--no-accept-flake-config', evaluate.call_args.args[0])
            graph['media']['newInput'] = 'changed'
            second = reuse.evaluated_inputs(ROOT)
            self.assertNotEqual(first['media_input'], second['media_input'])
            self.assertEqual(first['evidence_input'], second['evidence_input'])

    def test_runtime_flag_never_supplies_missing_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'proof.json'
            github_output = Path(directory) / 'github-output'
            arguments = ['decision_only.py', '--config', 'unused', '--output', str(output), 'verify']
            environment = {'CI_PLAN': json.dumps({'retained_evidence': {'source': 'a' * 40}}),
                           'GITHUB_ACTOR': 'fixture', 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1',
                           'GITHUB_OUTPUT': str(github_output), 'MAESTRO_DECISION_ONLY_REUSE_ENABLED': 'true'}
            with patch.dict(os.environ, environment), patch.object(sys, 'argv', arguments), \
                 patch.object(reuse.common, 'config', return_value={}), \
                 patch.object(reuse.operations, 'run', return_value=SimpleNamespace(returncode=0)), \
                 patch.object(reuse, 'verify', side_effect=reuse.authority.HumanDecisionRequired('review revoked')), redirect_stdout(io.StringIO()):
                self.assertEqual(reuse.main(), 2)
                self.assertEqual(json.loads(output.read_text())['status'], 'blocked')
                self.assertFalse(github_output.exists())


class PublicationIntent(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.event = Path(self.temporary.name) / 'event.json'
        self.event.write_text(json.dumps({'workflow_run': {'id': 500, 'head_sha': 'c' * 40}}))
        self.cfg = {'repository': 'closure-labs/maestro'}
        self.producer = {'workflow': '.github/workflows/ci.yml', 'runId': 100, 'runAttempt': 2, 'revision': 'a' * 40}
        self.product = {'revision': 'a' * 40, 'assets': {}}
        self.product_decision, self.security_decision = '3' * 64, '4' * 64
        old_packet = {'producer': dict(self.producer, runId=50, repository=self.cfg['repository'], sourceRevision='a' * 40)}
        current_packet = {'producer': dict(self.producer, repository=self.cfg['repository'], sourceRevision='a' * 40)}
        self.release = {'kind': 'release-product', 'payload': {'disposition': 'accepted', 'product': self.product, 'packet': old_packet}}
        self.security = {'kind': 'security-findings', 'payload': {'disposition': 'accepted', 'packet': current_packet}}
        self.records = {self.product_decision: self.release, self.security_decision: self.security}
        self.hint = {'schema': 1, 'status': 'verified', 'eligible': True, 'reused': True, 'source': 'c' * 40,
                     'runId': 500, 'runAttempt': 1, 'productHash': reuse.common.canonical_hash(self.product),
                     'productDecisionHash': self.product_decision, 'securityDecisionHash': self.security_decision,
                     'producer': self.producer}
        self.patch(patch.dict(os.environ, {'MAESTRO_DECISION_ONLY_REUSE_ENABLED': 'true',
            'GITHUB_EVENT_NAME': 'workflow_run', 'GITHUB_EVENT_PATH': str(self.event)}, clear=True))
        self.patch(patch.object(reuse.common, 'verify_producer'))
        self.patch(patch.object(reuse.common, 'active_release', return_value=(self.product_decision, self.release)))
        self.patch(patch.object(reuse.common, 'active_security', return_value=(self.security_decision, self.security)))
        self.api = self.patch(patch.object(reuse.authority, 'github_api', side_effect=self.metadata))
        self.patch(patch.object(reuse.operations, 'run', side_effect=self.download))

    def patch(self, value):
        self.addCleanup(value.stop)
        return value.start()

    def archive(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as source:
            source.writestr('retained-publication-intent.json', json.dumps(self.hint))
        return stream.getvalue()

    def metadata(self, endpoint):
        if '/artifacts?' in endpoint:
            raw = self.archive()
            return {'total_count': 1, 'artifacts': [{'id': 700, 'name': 'maestro-retained-publication-intent-500-1',
                    'expired': False, 'size_in_bytes': len(raw), 'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}]}
        return {'id': 500, 'run_attempt': 1, 'head_sha': 'c' * 40, 'path': '.github/workflows/ci.yml'}

    def download(self, arguments, **kwargs):
        kwargs['stdout'].write(self.archive())
        return SimpleNamespace(returncode=0)

    def test_hint_normalizes_exact_current_product_and_fresh_scan_producer(self):
        result = reuse.publication_intent(self.cfg, self.records)
        self.assertEqual(result['productDecisionHash'], self.product_decision)
        self.assertEqual(result['securityDecisionHash'], self.security_decision)
        self.assertEqual(result['decisionHash'], self.security_decision)
        self.assertEqual(result['proposal'], self.security)

    def test_manual_selectors_are_never_overridden(self):
        for key, value in (('CANDIDATE_RUN', '123'), ('CANDIDATE_PROPOSAL_HASH', 'f' * 64), ('CANDIDATE_RELEASE_ONLY', 'true')):
            with patch.dict(os.environ, {key: value}), self.subTest(key=key):
                self.assertIsNone(reuse.publication_intent(self.cfg, self.records))
        self.api.assert_not_called()

    def test_changed_product_or_confused_decision_ids_cannot_select_another_product(self):
        self.hint['productHash'] = 'f' * 64
        with self.assertRaises(ValueError):
            reuse.publication_intent(self.cfg, self.records)

    def test_explicit_workflow_filter_is_preserved(self):
        with patch.dict(os.environ, {'CANDIDATE_WORKFLOW': '.github/workflows/security.yml'}), self.assertRaises(ValueError):
            reuse.publication_intent(self.cfg, self.records)
        self.hint['productHash'] = reuse.common.canonical_hash(self.product)
        self.hint['productDecisionHash'] = self.security_decision
        with self.assertRaises(ValueError):
            reuse.publication_intent(self.cfg, self.records)


if __name__ == '__main__':
    unittest.main()
