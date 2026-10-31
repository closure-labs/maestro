# SPDX-License-Identifier: Apache-2.0
"""Local health is a negative filter, never a cached publication decision."""
from copy import deepcopy
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / 'modules/ci/authority/_source/decisions'))
sys.path.insert(0, str(ROOT / 'modules/ci/authority/_tests'))
import common
import publication_preflight as preflight
import test_readonly_preflight as readonly

NOW = dt.datetime(2026, 10, 31, 12, tzinfo=dt.timezone.utc)


class Clock(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz else NOW.replace(tzinfo=None)


class HealthPreflight(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.product = dict(schema=1, repository='closure-labs/maestro', revision='a' * 40,
                            products={'maestro': {'storePath': '/nix/store/' + 'a' * 32 + '-runtime',
                                                  'narHash': 'sha256-' + 'A' * 43 + '='}}, roots={}, assets={})
        native = dict(status='complete', scannerHealth='healthy', scannedAt=(NOW - dt.timedelta(minutes=1)).isoformat(),
                      database=dict(valid=True, built=(NOW - dt.timedelta(hours=1)).isoformat()))
        self.scans = dict(schema=1, repository=self.product['repository'], revision=self.product['revision'],
                          producer=dict(workflow='.github/workflows/ci.yml', runId=123, runAttempt=1),
                          scannedAt=(NOW - dt.timedelta(minutes=2)).isoformat(),
                          expiresAt=(NOW + dt.timedelta(hours=1)).isoformat(), profiles={'maestro': native})
        self.policy = json.loads((ROOT / 'modules/ci/authority/_source/decision-policy.json').read_text())
        self.write()

    def write(self):
        for name in ('product', 'scans', 'policy'):
            (self.root / (name + '.json')).write_text(json.dumps(getattr(self, name)))

    def check(self):
        with patch.object(preflight.dt, 'datetime', Clock), \
                patch.object(common.authority, 'github_api', side_effect=AssertionError('GitHub read reached')), \
                patch.object(preflight.destinations, 'http', side_effect=AssertionError('public transport reached')):
            return preflight.readiness(*(self.root / (name + '.json') for name in ('product', 'scans', 'policy')))

    def test_fresh_input_is_only_a_non_authoritative_continuation(self):
        self.assertEqual(self.check(), {'schema': 1, 'status': 'not-rejected-by-local-health', 'authorityClaim': False})
        self.assertEqual({p.name for p in self.root.iterdir()}, {'scans.json', 'product.json', 'policy.json'})

    def test_expired_future_malformed_missing_and_unhealthy_inputs_are_rejected(self):
        original = deepcopy(self.scans)
        changes = [lambda s: s.update(expiresAt=NOW.isoformat()),
                   lambda s: s.update(scannedAt=(NOW + dt.timedelta(minutes=1)).isoformat()),
                   lambda s: s.update(expiresAt='malformed'), lambda s: s.pop('scannedAt'),
                   lambda s: s.update(profiles={}), lambda s: s.update(profiles={'other': {}}),
                   lambda s: s['profiles']['maestro'].update(status='incomplete'),
                   lambda s: s['profiles']['maestro'].update(scannerHealth='unhealthy'),
                   lambda s: s['profiles']['maestro'].update(database=None),
                   lambda s: s['profiles']['maestro']['database'].update(valid=False),
                   lambda s: s['profiles']['maestro']['database'].update(built=(NOW - dt.timedelta(hours=49)).isoformat()),
                   lambda s: s['profiles']['maestro']['database'].update(built=(NOW + dt.timedelta(minutes=1)).isoformat()),
                   lambda s: s['profiles']['maestro'].update(scannedAt=NOW.replace(tzinfo=None).isoformat())]
        for change in changes:
            self.scans = deepcopy(original)
            change(self.scans)
            self.write()
            with self.subTest(change=change), self.assertRaises((ValueError, KeyError, TypeError)):
                self.check()
        (self.root / 'scans.json').unlink()
        with self.assertRaises(OSError):
            self.check()

    def test_disabled_or_invalid_local_age_policy_is_negative_readiness(self):
        for field, value in (('enabled', False), ('maxEvidenceAgeHours', True), ('maxDatabaseAgeHours', 0)):
            original = deepcopy(self.policy)
            self.policy[field] = value
            self.write()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check()
            self.policy = original

    def test_duplicate_fields_symlinks_and_changed_product_identity_fail_before_probes(self):
        (self.root / 'scans.json').write_text('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):
            self.check()
        self.write()
        (self.root / 'scans.json').rename(self.root / 'actual.json')
        (self.root / 'scans.json').symlink_to(self.root / 'actual.json')
        with self.assertRaises(OSError):
            self.check()
        (self.root / 'scans.json').unlink()
        self.product['revision'] = 'b' * 40
        self.write()
        with self.assertRaises(ValueError):
            self.check()

    def test_request_count_expired_zero_fresh_preserves_probe_and_final_gate(self):
        # Deterministic request-count fixture, not a hosted timing claim. The
        # transport fanout mirrors the measured official publication run.
        def pipeline():
            self.check()
            calls['public'] += 2799
            with patch.object(common, 'gate', wraps=common.gate) as gate:
                try:
                    self.revoked_gate()
                finally:
                    calls['gate'] += gate.call_count
        calls = {'public': 0, 'gate': 0}
        self.scans['expiresAt'] = NOW.isoformat()
        self.write()
        with self.assertRaises(ValueError):
            pipeline()
        self.assertEqual(calls, {'public': 0, 'gate': 0})
        self.scans['expiresAt'] = (NOW + dt.timedelta(hours=1)).isoformat()
        self.write()
        with self.assertRaisesRegex(ValueError, 'Current human risk acceptance required'):
            pipeline()
        self.assertEqual(calls, {'public': 2799, 'gate': 1})

    def revoked_gate(self):
        # Keep the real final gate/scans/admission path. Isolate only external
        # repository, provenance and current-decision reads from this fixture.
        with patch.object(common.dt, 'datetime', Clock), \
                patch.object(common, 'required_check'), \
                patch.object(common, 'ledger', return_value=('a' * 40, {})), \
                patch.object(common, 'verify_producer', return_value=('a' * 40, '.github/workflows/ci.yml')), \
                patch.object(common, 'attest'), \
                patch.object(common, 'active_security', return_value=('b' * 64, {'payload': {'disposition': 'revoked'}})):
            common.gate(dict(self.policy, requiredCoverage={}), self.root / 'scans.json', self.root / 'product.json',
                        api=lambda endpoint: {'status': 'identical'})

    def test_fresh_metadata_does_not_hide_current_revocation(self):
        self.check()
        with self.assertRaisesRegex(ValueError, 'Current human risk acceptance required'):
            self.revoked_gate()

    def test_expiry_or_tampering_after_preflight_still_fails_native_authentication(self):
        self.check()
        self.scans['expiresAt'] = NOW.isoformat()
        self.write()
        with patch.object(common.dt, 'datetime', Clock), self.assertRaisesRegex(ValueError, 'Expired or future native health'):
            common.scans(self.root / 'scans.json', self.policy)
        self.scans['expiresAt'] = (NOW + dt.timedelta(hours=1)).isoformat()
        self.write()
        self.check()  # Tampered fresh-looking data can only pass this local filter.
        with patch.object(common.dt, 'datetime', Clock), \
                patch.object(common, 'verify_producer', return_value=('a' * 40, '.github/workflows/ci.yml')), \
                patch.object(common, 'attest', side_effect=ValueError('signature mismatch')) as attest, \
                self.assertRaisesRegex(ValueError, 'signature mismatch'):
            common.scans(self.root / 'scans.json', self.policy)
        attest.assert_called_once()

    def test_workflows_apply_filter_before_destination_probe_without_removing_final_gates(self):
        for filename in ('publication.yml', 'release-publication.yml'):
            workflow = json.loads(subprocess.check_output(['yq', '-o=json', '.',
                                  str(ROOT / '.github/workflows' / filename)], text=True))
            steps = workflow['jobs']['publish']['steps']
            health = next(i for i, s in enumerate(steps) if s.get('run', '').endswith(' ci:decision:health-preflight'))
            inspect = next(i for i, s in enumerate(steps) if s.get('run', '').endswith(' release:inspect'))
            download = next(i for i, s in enumerate(steps) if s.get('run', '').endswith(' ci:decision:download'))
            self.assertLess(download, health)
            self.assertLess(health, inspect)
            final = ' ci:decision:publication' if filename == 'publication.yml' else ' release:assets'
            self.assertTrue(any(s.get('run', '').endswith(final) for s in steps))

    def test_native_leaf_rejects_missing_data_without_emitting_readiness(self):
        env = dict(os.environ, MAESTRO_DECISIONS_SOURCE=str(ROOT / 'modules/ci/authority/_source/decisions'),
                   MAESTRO_SYSTEM_ROOT=str(ROOT), DECISION_PRODUCT=str(self.root / 'product.json'),
                   DECISION_SCANS=str(self.root / 'missing.json'))
        result = subprocess.run(['bash', str(ROOT / 'modules/ci/authority/_source/decision-health-preflight.sh')],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_native_leaf_fresh_input_can_only_continue_to_the_real_gate(self):
        now = dt.datetime.now(dt.timezone.utc)
        self.scans['scannedAt'] = (now - dt.timedelta(minutes=2)).isoformat()
        self.scans['expiresAt'] = (now + dt.timedelta(hours=1)).isoformat()
        self.scans['profiles']['maestro']['scannedAt'] = (now - dt.timedelta(minutes=1)).isoformat()
        self.scans['profiles']['maestro']['database']['built'] = (now - dt.timedelta(hours=1)).isoformat()
        self.write()
        env = dict(os.environ, MAESTRO_DECISIONS_SOURCE=str(ROOT / 'modules/ci/authority/_source/decisions'),
                   MAESTRO_SYSTEM_ROOT=str(ROOT), DECISION_PRODUCT=str(self.root / 'product.json'),
                   DECISION_SCANS=str(self.root / 'scans.json'))
        result = subprocess.run(['bash', str(ROOT / 'modules/ci/authority/_source/decision-health-preflight.sh')],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['authorityClaim'], False)
        self.assertEqual(json.loads(result.stdout)['status'], 'not-rejected-by-local-health')

    def test_actual_readonly_publisher_expired_input_makes_zero_public_requests(self):
        harness = readonly.ReadonlyPreflight('test_verified_only_trial_keeps_one_fresh_gate_and_no_transfers')
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        scans = json.loads((harness.work / 'scans.json').read_text())
        scans['scannedAt'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=25)).isoformat()
        scans['expiresAt'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
        (harness.work / 'scans.json').write_text(json.dumps(scans))
        result, calls = harness.run_leaf(already_verified=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertFalse(harness.receipt.exists())


if __name__ == '__main__':
    unittest.main()
