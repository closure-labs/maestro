# SPDX-License-Identifier: Apache-2.0
"""Selected cache contracts never narrow complete evidence or import authority."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / 'modules/ci/authority/_source/decisions'))
import cache_publication as policy
import common
import destinations
import publication_receipts
import verification_context


def store(letter, name):
    return '/nix/store/' + letter * 32 + '-' + name


HASH = 'sha256-' + 'A' * 43 + '='
OTHER = 'sha256-' + 'B' * 43 + '='
NAMES = ['maestro-menu', 'maestroctl', 'deploy-template', 'sbomnix']
SELECTED = {name: store(str(i), name) for i, name in enumerate(NAMES)}
STOCK = store('4', 'runtime')
SYSTEM = store('5', 'appliance')
ISO = store('6', 'installer')
TOOLCHAIN = store('7', 'ci-toolchain')
EXTRA = [store('8', 'system-dependency'), store('9', 'installer-dependency')]
CACHE = 'https://maestro.cachix.org'
NIXOS = 'https://cache.nixos.org'
XO = 'https://xen-orchestra-ce.cachix.org'


class CachePublication(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / 'modules/ci/authority/_source/decision-policy.json').read_text())
        self.product = dict(schema=1, repository='closure-labs/maestro', revision='a' * 40,
                            products={'maestro': {'storePath': SYSTEM, 'narHash': HASH}}, assets={}, roots={})
        for name, path in {**SELECTED, 'installer': ISO, 'maestro-ci-toolchain': TOOLCHAIN}.items():
            self.product['roots'][name] = dict(storePath=path, narHash=HASH, profile='maestro')
        self.rows = {path: {'narHash': HASH, 'references': [STOCK]} for path in SELECTED.values()}
        self.rows[STOCK] = {'narHash': HASH, 'references': []}
        self.before = deepcopy(self.product)
        policy.attach(self.product, self.config, lambda paths: self.rows)
        self.retained = {path: {'narHash': HASH} for path in [*self.rows, SYSTEM, ISO, TOOLCHAIN, *EXTRA]}

    def test_producer_adds_scope_without_removing_complete_signed_subjects(self):
        self.assertEqual({key: value for key, value in self.product.items() if key != 'cachePublication'}, self.before)
        self.assertEqual(set(policy.identities(self.product, self.config)), set(SELECTED.values()))
        self.assertEqual(policy.closure(self.product), self.rows)
        plans = json.loads((ROOT / 'modules/ci/graph/_lib/plans.json').read_text())
        self.assertEqual(len(plans['validation']['targets']), 20)
        self.assertIn('toplevel', [row['name'] for row in plans['publish']['targets']])
        self.assertIn('maestro-ci-toolchain', [row['name'] for row in plans['publish']['targets']])
        self.assertIn('sbomnix-materialize-metadata.patch', (ROOT / 'modules/ci/inventory/_lib/sbomnix.nix').read_text())

    def test_cache_policy_verifier_participates_in_gate_local_identity_binding(self):
        baseline = verification_context.verifier_version()
        original = Path.read_bytes
        def changed(path):
            value = original(path)
            return value + b'\n# changed policy verifier\n' if path.name == 'cache_publication.py' else value
        with patch.object(Path, 'read_bytes', changed):
            self.assertNotEqual(verification_context.verifier_version(), baseline)

    def test_scope_contains_only_exact_reachable_native_and_retained_identities(self):
        result = policy.scoped_metadata(self.product, self.retained, lambda paths: self.rows)
        self.assertEqual(set(result), {*SELECTED.values(), STOCK})
        self.assertEqual(set(self.retained), {*SELECTED.values(), STOCK, SYSTEM, ISO, TOOLCHAIN, *EXTRA})
        for path in result:
            self.assertEqual(result[path], self.retained[path])

    def test_missing_changed_or_unrelated_signed_dependencies_fail_closed(self):
        mutations = [lambda r: r.pop(STOCK), lambda r: r[STOCK].update(narHash=OTHER),
                     lambda r: r.update({SYSTEM: {'narHash': HASH, 'references': []}}),
                     lambda r: r[next(iter(SELECTED.values()))].update(references=[SYSTEM]),
                     lambda r: r[STOCK].update(references=[STOCK, STOCK])]
        for change in mutations:
            rows = deepcopy(self.rows)
            change(rows)
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy.scoped_metadata(self.product, self.retained, lambda paths: rows)
        retained = deepcopy(self.retained)
        retained[STOCK]['narHash'] = OTHER
        with self.assertRaises(ValueError):
            policy.scoped_metadata(self.product, retained, lambda paths: self.rows)

    def test_policy_mutation_missing_root_or_untyped_contract_is_rejected(self):
        for change in (lambda p: p['cachePublication']['roots'].append('installer'),
                       lambda p: p['roots'].pop('maestro-menu'),
                       lambda p: p['cachePublication'].update(schema=True),
                       lambda p: p['cachePublication']['roots'].append('maestro-menu')):
            value = deepcopy(self.product)
            change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy.identities(value, self.config, required=True)

    def test_historical_full_contract_is_readable_but_cannot_select_new_uploads(self):
        self.assertIn(SYSTEM, policy.identities(self.before))
        self.assertIn(ISO, policy.identities(self.before))
        with self.assertRaisesRegex(ValueError, 'qualify a new signed product'):
            policy.identities(self.before, self.config, required=True)

    def read(self, calls, missing=False, conflict=False, expired=False, full=False):
        rows = deepcopy(self.rows)
        if full:
            rows.update({SYSTEM: {'narHash': HASH, 'references': [EXTRA[0]]},
                         ISO: {'narHash': HASH, 'references': [EXTRA[1]]},
                         TOOLCHAIN: {'narHash': HASH, 'references': []},
                         **{path: {'narHash': HASH, 'references': []} for path in EXTRA}})
        def fetch(url):
            calls.append(url)
            path = next((p for p in rows if Path(p).name.startswith(url.rsplit('/', 1)[1].removesuffix('.narinfo'))), None)
            if path is None or (path == STOCK and (url.startswith(CACHE) or missing)):
                return 404, b''
            if path == STOCK and expired:
                return 410, b''
            row = rows[path]
            digest = OTHER if path == STOCK and conflict else row['narHash']
            return 200, ('StorePath: '+path+'\nNarHash: '+digest+'\nNarSize: 1\nURL: nar/fixture.nar.zst\nReferences: '
                         +' '.join(Path(p).name for p in row['references'])+'\n').encode()
        return fetch

    def test_public_verification_probes_only_selected_closures_and_preserves_upstream_dedup(self):
        calls = []
        result = destinations.cache(self.product, CACHE, read=self.read(calls), upstreams=(NIXOS, XO))
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(set(result['expected']), set(SELECTED.values()))
        self.assertFalse(any(Path(path).name[:32] in call for call in calls for path in (SYSTEM, ISO, TOOLCHAIN)))
        self.assertTrue(any(call.startswith(NIXOS) for call in calls))
        receipt = destinations.receipt(result, self.product)
        self.assertEqual(receipt['productHash'], common.canonical_hash(self.product))
        self.assertNotIn(SYSTEM, receipt['expected'])
        old_calls = []
        self.assertEqual(destinations.cache(self.before, CACHE, read=self.read(old_calls, full=True), upstreams=(NIXOS, XO))['status'], 'verified')
        self.assertLess(len(calls), len(old_calls))
        print(json.dumps({'fixtureLegacyPublicRequests': len(old_calls), 'fixtureSelectedPublicRequests': len(calls),
                          'fixtureSelectedRootCount': len(result['expected']), 'hostedMeasurement': False}))

    def test_journal_cannot_mislabel_selected_scope_as_complete_distribution_cache(self):
        result = destinations.cache(self.product, CACHE, read=self.read([]), upstreams=(NIXOS, XO))
        receipt = destinations.receipt(result, self.product)
        publication_receipts.cache_scope(receipt, self.product)
        receipt['expected'][SYSTEM] = HASH
        receipt['observed'][SYSTEM] = HASH
        with self.assertRaisesRegex(ValueError, 'differs from signed'):
            publication_receipts.cache_scope(receipt, self.product)

    def test_missing_expired_and_conflicting_upstream_never_produce_false_verified_receipt(self):
        for options, expected in (({'missing': True}, 'partial'), ({'expired': True}, 'unavailable'), ({'conflict': True}, 'conflict')):
            with self.subTest(options=options):
                result = destinations.cache(self.product, CACHE, read=self.read([], **options), upstreams=(NIXOS, XO))
                self.assertEqual(result['status'], expected)
                with self.assertRaises(ValueError):
                    destinations.receipt(result, self.product)
        metadata = policy.scoped_metadata(self.product, self.retained, lambda paths: self.rows)
        metadata[SYSTEM] = self.retained[SYSTEM]
        with self.assertRaisesRegex(ValueError, 'differs from signed'):
            destinations.cache(self.product, CACHE, read=self.read([]), upstreams=(NIXOS, XO), closure=metadata)

    def test_remote_reference_omission_or_injection_cannot_redefine_signed_closure(self):
        for references in ('', Path(SYSTEM).name):
            base = self.read([])
            def altered(url):
                status, body = base(url)
                if Path(SELECTED['maestro-menu']).name[:32] in url and status == 200:
                    body = body.replace(('References: '+Path(STOCK).name).encode(), ('References: '+references).encode())
                return status, body
            with self.subTest(references=references):
                result = destinations.cache(self.product, CACHE, read=altered, upstreams=(NIXOS, XO))
                self.assertEqual(result['status'], 'conflict')
                with self.assertRaises(ValueError):
                    destinations.receipt(result, self.product)

    def test_full_product_security_validation_still_rejects_unselected_root_mismatch(self):
        value = deepcopy(self.product)
        value['products']['maestro']['narHash'] = OTHER
        native = {'profiles': {'maestro': {'subjects': [{'storePath': SYSTEM, 'narHash': HASH}]}}, 'revision': value['revision']}
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'product.json'
            path.write_text(json.dumps(value))
            with patch.object(common, 'attest_product', side_effect=AssertionError('Invalid distribution reached signature')):
                with self.assertRaisesRegex(ValueError, 'absent from authenticated scanned subjects'):
                    common.product(path, self.config, native)

    def test_actual_publisher_uploads_only_selected_missing_closure_after_full_restore(self):
        sys.path.insert(0, str(ROOT / 'modules/ci/authority/_tests'))
        import test_publish_readback as readback
        harness = readback.PublishReadback('test_verified_noop_has_no_restore_handoff_or_upload')
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        harness.product['cachePublication']['roots'] = ['0']
        path = harness.work / 'controller/modules/ci/authority/_source/decision-policy.json'
        checked = json.loads(path.read_text())
        checked['cachePublication']['roots'] = ['0']
        path.write_text(json.dumps(checked))
        root = harness.product['roots']['0']['storePath']
        dependency = harness.paths[4]
        result, calls = harness.run_leaf(references={root: [dependency]})
        self.assertEqual(result.returncode, 0, result.stderr)
        uploaded = next(call[1:] for call in calls if call[0] == 'uploaded')
        self.assertEqual(set(uploaded), {root, dependency})
        self.assertEqual(len(harness.local), 8)  # Complete retained distribution remains independent.
        self.assertTrue(any(call[0] == 'maestro-ci-distribution-restore' for call in calls))
        self.assertGreaterEqual(sum(call[0] == 'maestro-ci-decision-publication' for call in calls), 3)
        receipt = json.loads(harness.receipt.read_text())
        self.assertEqual(set(receipt['expected']), {root})
        self.assertEqual(receipt['productHash'], common.canonical_hash(harness.product))

    def test_consumer_verifies_selected_roots_and_every_signed_dependency_without_builders(self):
        spec = importlib.util.spec_from_file_location('selected_consumer', ROOT / 'modules/release/consumer/_source/consumer-probe.py')
        consumer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(consumer)
        calls = []
        def execute(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps(self.rows))
        result = consumer.probe(self.product, CACHE, 'approved-key', execute)
        self.assertEqual(result['roots'], 4)
        self.assertNotIn(SYSTEM, calls[0])
        self.assertNotIn(ISO, calls[0])
        self.assertIn('--recursive', calls[-1])
        self.assertIn('--recursive', calls[1])
        self.assertIn('--sigs-needed', calls[1])
        for key, value in (('max-jobs', '0'), ('builders', ''), ('fallback', 'false'), ('require-sigs', 'true')):
            self.assertIn(['--option', key, value], [calls[0][i:i+3] for i in range(len(calls[0])-2)])
        bad = deepcopy(self.rows)
        bad[STOCK]['narHash'] = OTHER
        with self.assertRaises(ValueError):
            consumer.probe(self.product, CACHE, 'approved-key', lambda args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps(bad)))


if __name__ == '__main__':
    unittest.main()
