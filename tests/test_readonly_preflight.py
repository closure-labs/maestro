# SPDX-License-Identifier: Apache-2.0
"""Exercise both flag states against the same approved-data/public-cache fixture."""
import json
import hashlib
import datetime as dt
import os
from pathlib import Path
import sys
import subprocess
import unittest
from unittest.mock import patch

import test_publish_readback as readback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'nix/automation/decisions'))
import publication_preflight


class ReadonlyPreflight(readback.PublishReadback):
    def setUp(self):
        super().setUp()
        original = self.product['products']
        self.product['products'] = {'maestro': original['latest']}
        self.product['roots'].update({'fixture-stable': original['stable'], 'fixture-rolling': original['rolling']})
        self.product['schema'] = 1
        (self.work / 'product.json').write_text(json.dumps(self.product))
        now = dt.datetime.now(dt.timezone.utc)
        native = {'status': 'complete', 'scannerHealth': 'healthy', 'scannedAt': now.isoformat(),
                  'database': {'valid': True, 'built': now.isoformat()}}
        scans = {'schema': 1, 'repository': self.product['repository'], 'revision': self.product['revision'],
                 'scannedAt': now.isoformat(), 'expiresAt': (now + dt.timedelta(hours=24)).isoformat(),
                 'profiles': {'maestro': native}}
        (self.work / 'scans.json').write_text(json.dumps(scans))
        policy_root = self.work / 'controller'
        self.policy = policy_root / 'nix/automation/decision-policy.json'
        self.policy.parent.mkdir(parents=True)
        self.policy.write_bytes((ROOT / 'nix/automation/decision-policy.json').read_bytes())
        self.env.update(MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED='true',
                        MAESTRO_SYSTEM_ROOT=str(policy_root),
                        GH_TOKEN='private-reader', REGISTRY_TOKEN='private-registry',
                        XO_AUTHORITY_TOKEN='private-upstream')

    def test_same_data_flag_off_on_pair_has_one_fresh_gate_in_verified_path(self):
        self.env['MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED'] = 'false'
        result, off = self.run_leaf(already_verified=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        off_receipt = json.loads(self.receipt.read_text())
        self.calls.unlink()
        self.receipt.unlink()
        self.env['MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED'] = 'true'
        result, on = self.run_leaf(already_verified=True, require_public_environment=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(call[0] == 'maestro-ci-decision-publication' for call in off), 2)
        self.assertEqual(sum(call[0] == 'maestro-ci-decision-publication' for call in on), 1)
        self.assertLess(next(i for i, call in enumerate(on) if call[0] == 'curl'),
                        next(i for i, call in enumerate(on) if call[0] == 'maestro-ci-decision-publication'))
        self.assertFalse(any(call[0] in ('cachix', 'maestro-ci-distribution-restore') for call in on))
        on_receipt = json.loads(self.receipt.read_text())
        for field in ('schema', 'productHash', 'destination', 'status', 'expected', 'observed', 'verifier'):
            self.assertEqual(on_receipt[field], off_receipt[field])

    def test_verified_only_trial_keeps_one_fresh_gate_and_no_transfers(self):
        self.env['PUBLICATION_REQUIRE_VERIFIED'] = 'true'
        result, calls = self.run_leaf(already_verified=True, require_public_environment=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(call[0] == 'maestro-ci-decision-publication' for call in calls), 1)
        self.assertFalse(any(call[0] in ('cachix', 'maestro-ci-distribution-restore') for call in calls))
        self.assertEqual(json.loads(self.receipt.read_text())['status'], 'verified')

    def test_trial_partial_cache_cannot_import_write_or_create_receipt(self):
        self.env['PUBLICATION_REQUIRE_VERIFIED'] = 'true'
        result, calls = self.run_leaf(existing=self.paths[:-1], require_public_environment=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(call[0] == 'curl' for call in calls))
        self.assertFalse(any(call[0] in ('cachix', 'maestro-ci-distribution-restore') for call in calls))
        self.assertFalse(self.receipt.exists())

    def test_revoked_admission_or_mutated_inputs_cannot_create_receipt_or_complete(self):
        for settings in ({'deny_authority_at': 1}, {'mutate_input_at': 1}):
            with self.subTest(settings=settings):
                result, calls = self.run_leaf(already_verified=True, **settings)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.receipt.exists())
                self.assertFalse(any(call[0] in ('cachix', 'maestro-ci-distribution-restore') for call in calls))
                self.calls.unlink()

    def test_partial_destination_keeps_all_original_authority_and_handoff_gates(self):
        result, calls = self.run_leaf(require_public_environment=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        gates = [i for i, call in enumerate(calls) if call[0] == 'maestro-ci-decision-publication']
        restore = next(i for i, call in enumerate(calls) if call[0] == 'maestro-ci-distribution-restore')
        handoff = next(i for i, call in enumerate(calls) if call[0] == 'maestro-ci-decision-handoff')
        push = next(i for i, call in enumerate(calls) if call[0] == 'cachix')
        self.assertEqual(len(gates), 3)
        self.assertLess(gates[0], restore)
        self.assertLess(gates[1], handoff)
        self.assertLess(handoff, gates[2])
        self.assertLess(gates[2], push)

    def test_invalid_input_shape_blocks_even_public_inspection(self):
        (self.work / 'scans.json').write_text('{}')
        result, calls = self.run_leaf(already_verified=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_duplicate_or_nonfinite_json_is_not_validated_structure(self):
        for raw in ('{"schema":1,"schema":1}', '{"schema":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                publication_preflight.document(raw)

    def test_mutated_original_or_snapshot_cannot_be_treated_as_frozen(self):
        directory = self.work / 'frozen'
        digest = publication_preflight.freeze(self.work / 'product.json', self.work / 'scans.json', directory, self.policy)
        (directory / 'product.json').chmod(0o600)
        (directory / 'product.json').write_text('{}')
        with self.assertRaises(ValueError):
            publication_preflight.unchanged(directory, digest)

    def test_buffer_from_before_this_execution_cannot_be_freshened_into_a_receipt(self):
        directory = self.work / 'frozen'
        digest = publication_preflight.freeze(self.work / 'product.json', self.work / 'scans.json', directory, self.policy)
        observation = self.work / 'observation.json'
        expected = dict(self.local)
        observation.write_text(json.dumps({'schema': 1, 'destination': 'cache', 'status': 'verified',
            'expected': expected, 'observed': expected, 'missing': [], 'authorityClaim': False}))
        os.utime(observation, (0, 0))
        with self.assertRaises(ValueError):
            publication_preflight.complete(directory, observation, self.receipt, digest, hashlib.sha256(observation.read_bytes()).hexdigest())
        self.assertFalse(self.receipt.exists())

    def test_rewritten_metadata_cannot_hide_changed_inputs(self):
        directory = self.work / 'frozen'
        digest = publication_preflight.freeze(self.work / 'product.json', self.work / 'scans.json', directory, self.policy)
        metadata = directory / 'inputs.json'
        metadata.chmod(0o600)
        value = json.loads(metadata.read_text())
        value['files']['scans']['sha256'] = 'a' * 64
        metadata.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'snapshot metadata changed'):
            publication_preflight.unchanged(directory, digest)

    def test_changed_policy_cannot_relax_frozen_freshness_limits(self):
        directory = self.work / 'frozen'
        digest = publication_preflight.freeze(self.work / 'product.json', self.work / 'scans.json', directory, self.policy)
        value = json.loads(self.policy.read_text())
        value['maxDatabaseAgeHours'] = 168
        self.policy.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            publication_preflight.fresh(directory, digest)

    def test_late_native_expiry_blocks_completion_after_admission(self):
        directory = self.work / 'frozen'
        digest = publication_preflight.freeze(self.work / 'product.json', self.work / 'scans.json', directory, self.policy)
        expired = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
        with patch.object(publication_preflight.scheduling, 'observation_expiry', return_value=expired), self.assertRaises(ValueError):
            publication_preflight.complete(directory, self.work / 'unused-observation', self.receipt, digest, '0' * 64)
        self.assertFalse(self.receipt.exists())

    def test_long_admission_preserves_readback_time_and_existing_native_expiry(self):
        directory = self.work / 'frozen'
        now = dt.datetime.now(dt.timezone.utc).timestamp()
        with patch.object(publication_preflight.time, 'time', return_value=now - 600):
            digest = publication_preflight.freeze(self.work / 'product.json', self.work / 'scans.json', directory, self.policy)
        observation = self.work / 'observation.json'
        expected = dict(self.local)
        observation.write_text(json.dumps({'schema': 1, 'destination': 'cache', 'status': 'verified',
            'expected': expected, 'observed': expected, 'missing': [], 'authorityClaim': False}))
        os.utime(observation, (now - 180, now - 180))
        publication_preflight.complete(directory, observation, self.receipt, digest, hashlib.sha256(observation.read_bytes()).hexdigest())
        value = json.loads(self.receipt.read_text())
        self.assertAlmostEqual(dt.datetime.fromisoformat(value['verifiedAt']).timestamp(), observation.stat().st_mtime, places=5)

    def test_expiry_during_receipt_assembly_cannot_complete(self):
        directory = self.work / 'frozen'
        digest = publication_preflight.freeze(self.work / 'product.json', self.work / 'scans.json', directory, self.policy)
        observation = self.work / 'observation.json'
        observation.write_text(json.dumps({'schema': 1, 'destination': 'cache', 'status': 'verified',
            'expected': self.local, 'observed': self.local, 'missing': [], 'authorityClaim': False}))
        now = dt.datetime.now(dt.timezone.utc)
        with patch.object(publication_preflight.scheduling, 'observation_expiry',
                          side_effect=[now + dt.timedelta(seconds=60), now - dt.timedelta(seconds=1)]), self.assertRaises(ValueError):
            publication_preflight.complete(directory, observation, self.receipt, digest, hashlib.sha256(observation.read_bytes()).hexdigest())
        self.assertFalse(self.receipt.exists())

    def test_changed_buffer_cannot_produce_a_receipt(self):
        directory = self.work / 'frozen'
        digest = publication_preflight.freeze(self.work / 'product.json', self.work / 'scans.json', directory, self.policy)
        observation = self.work / 'observation.json'
        value = {'schema': 1, 'destination': 'cache', 'status': 'verified', 'expected': self.local,
                 'observed': self.local, 'missing': [], 'authorityClaim': False}
        observation.write_text(json.dumps(value))
        observed_hash = hashlib.sha256(observation.read_bytes()).hexdigest()
        observation.write_text(json.dumps(dict(value, localMutation=True)))
        with self.assertRaisesRegex(ValueError, 'observation changed'):
            publication_preflight.complete(directory, observation, self.receipt, digest, observed_hash)
        self.assertFalse(self.receipt.exists())

    def test_cli_failure_retains_bounded_structured_evidence_without_credentials(self):
        directory = self.work / 'frozen'
        digest = publication_preflight.freeze(self.work / 'product.json', self.work / 'scans.json', directory, self.policy)
        observation = self.work / 'observation.json'
        observation.write_text('{}')
        environment = dict(self.env, MAESTRO_CI_DIAGNOSTICS='true', RUNNER_TEMP=str(self.work))
        command = [sys.executable, str(ROOT / 'nix/automation/decisions/publication_preflight.py'), 'complete',
                   '--directory', str(directory), '--snapshot-digest', digest, '--observation', str(observation),
                   '--observation-digest', '0' * 64, '--receipt', str(self.receipt)]
        result = subprocess.run(command, env=environment, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertLessEqual(len(result.stderr.encode()), 4096)
        self.assertEqual(json.loads(result.stderr)['status'], 'blocked')
        self.assertNotIn('private-reader', result.stderr)
        self.assertFalse(self.receipt.exists())
        files = list((self.work / 'publication-diagnostics').glob('*.result.json'))
        self.assertEqual(len(files), 1)
        evidence = json.loads(files[0].read_text())
        self.assertEqual((evidence['operation'], evidence['reason']), ('complete', 'observation-changed'))


if __name__ == '__main__':
    unittest.main()
