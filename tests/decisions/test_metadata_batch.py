# SPDX-License-Identifier: Apache-2.0
"""Batch immutable metadata, never the live authorization following it."""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_packets import Registry, mod, sha
import common
import handoff as native_handoff

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('batch_handoff_fetch', ROOT / 'nix/automation/decision-handoff-fetch.py')
fetch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch)
FLAG = 'MAESTRO_PACKET_METADATA_BATCH_ENABLED'
NAMES = ('scans.json', 'product.json', 'handoff-xo-latest.json')


class MetadataBatch(unittest.TestCase):
    def setUp(self):
        self.patch(patch.object(mod, 'REGISTRY', 'ghcr.io/closure-labs/xo-nixpkg-products'))
        self.patch(patch.object(mod, 'REFERENCE', re.compile(re.escape(mod.REGISTRY) + r'@sha256:[0-9a-f]{64}')))
        self.patch(patch.dict(os.environ, {FLAG: 'false', 'MAESTRO_CI_DIAGNOSTICS': 'false'}))
        self.producer = {'runId': 7, 'runAttempt': 1, 'revision': 'a' * 40, 'workflow': '.github/workflows/ci.yml'}
        self.identity = {'storePath': '/nix/store/' + 'b' * 32 + '-xo', 'narHash': 'sha256-' + 'A' * 43 + '='}
        self.product = {'schema': 1, 'repository': 'closure-labs/xo-nixpkg', 'revision': 'a' * 40,
                        'products': {'xo-latest': self.identity}, 'roots': {}, 'assets': {}}
        now = dt.datetime.now(dt.timezone.utc)
        self.scan = {'schema': 1, 'repository': self.product['repository'], 'revision': self.product['revision'],
                     'producer': self.producer, 'scannedAt': (now - dt.timedelta(minutes=5)).isoformat(),
                     'expiresAt': (now + dt.timedelta(hours=1)).isoformat(),
                     'profiles': {'xo-latest': {'status': 'complete', 'scannerHealth': 'healthy',
                         'scannedAt': (now - dt.timedelta(minutes=1)).isoformat(),
                         'database': {'valid': True, 'built': (now - dt.timedelta(hours=1)).isoformat()}}}}

    def patch(self, manager):
        self.addCleanup(manager.stop)
        return manager.start()

    def data(self):
        handoff = {'schema': 1, 'repository': self.product['repository'], 'revision': self.product['revision'],
                   'channel': 'xo-latest', 'product': self.product, 'scans': self.scan}
        values = {'scans.json': self.scan, 'product.json': self.product, 'handoff-xo-latest.json': handoff}
        return {name: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode() for name, value in values.items()}

    def registry(self, data=None, records=None, descriptor=None):
        data = data or self.data()
        data = dict(data, **{'closure.tar.part-000': b'unrequested closure'})
        registry = Registry()
        files = {name: {'size': len(raw), 'sha256': sha(raw)} for name, raw in data.items()}
        files.update(records or {})
        registry.packet = descriptor or {'schema': 1, 'producer': self.producer, 'files': files}
        registry.packet_bytes = json.dumps(registry.packet).encode()
        registry.layers[:] = [registry.layer('decision-packet.json', registry.packet_bytes)] + [
            {'annotations': {'org.opencontainers.image.title': name}, 'digest': 'sha256:' + value['sha256'], 'size': value['size']}
            for name, value in files.items()]
        registry.blobs = {sha(raw): raw for raw in data.values()}
        registry.blobs[sha(registry.packet_bytes)] = registry.packet_bytes
        registry.refresh()
        return registry

    def transport(self, *registries):
        manifests = {r.reference: r.raw for r in registries}
        blobs = {key: value for r in registries for key, value in r.blobs.items()}
        def command(args, **kwargs):
            if args[1:3] == ['manifest', 'fetch']:
                return manifests[args[3]]
            self.assertEqual(args[1:3], ['blob', 'fetch'])
            digest = args[3].rsplit(':', 1)[1]
            self.assertNotEqual(digest, sha(b'unrequested closure'))
            Path(args[args.index('--output') + 1]).write_bytes(blobs[digest])
            return b''
        return command

    def policy(self, registry):
        return {'schema': 1, 'mode': 'official', 'repository': self.product['repository'], 'revision': self.product['revision'],
                'channel': 'xo-latest', **self.identity, 'packet': {'reference': registry.reference, 'sha256': mod.canonical_hash(registry.packet)}}

    def test_three_members_nine_to_five_operations_identical_raw_bytes(self):
        registry = self.registry()
        with patch.object(mod, 'command', side_effect=self.transport(registry)) as command:
            single = {name: mod.metadata_bytes(registry.reference, mod.canonical_hash(registry.packet), name, producer=self.producer) for name in NAMES}
            self.assertEqual(command.call_count, 9)
            command.reset_mock()
            many = mod.metadata_many(registry.reference, mod.canonical_hash(registry.packet), NAMES, producer=self.producer)
            self.assertEqual(command.call_count, 5)
        self.assertEqual(single, many)
        self.assertEqual(many, self.data())

    def test_descriptor_and_duplicate_requests_fetch_each_member_once(self):
        registry = self.registry()
        with patch.object(mod, 'command', side_effect=self.transport(registry)) as command:
            result = mod.metadata_many(registry.reference, mod.canonical_hash(registry.packet), ['decision-packet.json', 'scans.json', 'scans.json'])
        self.assertEqual(command.call_count, 3)
        self.assertEqual(result['decision-packet.json'], registry.packet_bytes)
        self.assertEqual(result['scans.json'], self.data()['scans.json'])

    def test_invalid_names_are_rejected_before_transport(self):
        registry = self.registry()
        for names in ([], 'scans.json', ['../scans.json'], ['/product.json'], [None], ['closure.tar.part-000'], list(NAMES) * 200):
            with self.subTest(names=str(names)[:40]), patch.object(mod, 'command') as command, self.assertRaises(ValueError):
                mod.metadata_many(registry.reference, mod.canonical_hash(registry.packet), names)
            command.assert_not_called()

    def test_missing_oversized_and_nested_bounds_block_before_member_fetch(self):
        for name, size in (('scans.json', 128*1024**2+1), ('product.json', 16*1024**2+1),
                           ('nested/scans.json', 16*1024**2+1), ('handoff-xo-latest.json', 128*1024**2+1)):
            registry = self.registry(records={name: {'size': size, 'sha256': 'a' * 64}})
            with self.subTest(name=name), patch.object(mod, 'command', side_effect=self.transport(registry)) as command, self.assertRaisesRegex(ValueError, 'oversized'):
                mod.metadata_many(registry.reference, mod.canonical_hash(registry.packet), [name])
            self.assertEqual(command.call_count, 1)
        registry = self.registry()
        with patch.object(mod, 'command', side_effect=self.transport(registry)) as command, self.assertRaisesRegex(ValueError, 'absent'):
            mod.metadata_many(registry.reference, mod.canonical_hash(registry.packet), ['missing.json'])
        self.assertEqual(command.call_count, 1)

    def test_wrong_manifest_descriptor_digest_and_producer_fail_closed(self):
        registry = self.registry()
        with patch.object(mod, 'command', side_effect=registry.command), self.assertRaisesRegex(ValueError, 'manifest digest'):
            mod.metadata_many(mod.REGISTRY + '@sha256:' + '0' * 64, mod.canonical_hash(registry.packet), NAMES)
        for expected, producer in [('f' * 64, self.producer), (mod.canonical_hash(registry.packet), dict(self.producer, runAttempt=True))]:
            with patch.object(mod, 'command', side_effect=self.transport(registry)) as command, self.assertRaises(ValueError):
                mod.metadata_many(registry.reference, expected, NAMES, producer=producer)
            self.assertEqual(command.call_count, 2)
        descriptor = copy.deepcopy(registry.packet)
        descriptor['files'].pop('product.json')
        broken = self.registry(descriptor=descriptor)
        with patch.object(mod, 'command', side_effect=self.transport(broken)), self.assertRaisesRegex(ValueError, 'contents differ'):
            mod.metadata_many(broken.reference, mod.canonical_hash(broken.packet), NAMES)

    def test_corrupt_or_malformed_descriptor_and_member_bytes_fail(self):
        registry = self.registry()
        base = self.transport(registry)
        def corrupt(args, **kwargs):
            if args[1:3] == ['blob', 'fetch'] and args[3].endswith(sha(self.data()['scans.json'])):
                Path(args[args.index('--output') + 1]).write_bytes(b'corrupt')
                return b''
            return base(args, **kwargs)
        with patch.object(mod, 'command', side_effect=corrupt), self.assertRaisesRegex(ValueError, 'integrity'):
            mod.metadata_many(registry.reference, mod.canonical_hash(registry.packet), NAMES)
        registry.packet_bytes = b'{'
        registry.layers[0] = registry.layer('decision-packet.json', registry.packet_bytes)
        registry.blobs[sha(registry.packet_bytes)] = registry.packet_bytes
        registry.refresh()
        with patch.object(mod, 'command', side_effect=self.transport(registry)), self.assertRaises(ValueError):
            mod.metadata_many(registry.reference, mod.canonical_hash(registry.packet), NAMES)

    def test_unavailable_transport_and_inherited_deadline_keep_failure_types(self):
        registry = self.registry()
        with patch.object(mod, 'command', side_effect=mod.RegistryUnavailable('Unavailable')), self.assertRaises(mod.RegistryUnavailable):
            mod.metadata_many(registry.reference, mod.canonical_hash(registry.packet), NAMES)
        with mod.operations.budget(-1), patch.object(mod, 'command') as command, self.assertRaises(subprocess.TimeoutExpired):
            mod.metadata_many(registry.reference, mod.canonical_hash(registry.packet), NAMES)
        command.assert_not_called()

    def test_handoff_default_singletons_and_enabled_batch_are_equivalent(self):
        registry = self.registry()
        policy = self.policy(registry)
        results = []
        for enabled in ('false', 'true'):
            with patch.dict(os.environ, {FLAG: enabled}), patch.object(mod, 'command', side_effect=self.transport(registry)) as command:
                results.append(fetch.handoff_documents(policy, policy, 'xo-latest'))
                self.assertEqual(command.call_count, 9 if enabled == 'false' else 5)
        self.assertEqual(results[0], results[1])
        for invalid in ('', 'TRUE', '1', 'yes'):
            with patch.dict(os.environ, {FLAG: invalid}), patch.object(mod, 'command') as command, self.assertRaisesRegex(ValueError, 'must be true or false'):
                fetch.handoff_documents(policy, policy, 'xo-latest')
            command.assert_not_called()

    def test_unset_flag_keeps_singleton_behavior(self):
        registry = self.registry()
        with patch.dict(os.environ):
            os.environ.pop(FLAG, None)
            with patch.object(mod, 'command', side_effect=self.transport(registry)) as command:
                fetch.handoff_documents(self.policy(registry), self.policy(registry), 'xo-latest')
            self.assertEqual(command.call_count, 9)

    def test_trial_workflow_and_native_inspector_prevent_partial_destination_writes(self):
        workflow = json.loads(subprocess.check_output(['yq', '-o=json', '.', str(ROOT / '.github/workflows/publication.yml')], text=True))
        trial = workflow['on']['workflow_dispatch']['inputs']['metadata_batch_trial']
        self.assertEqual(trial, {'description': 'Trial handoff metadata batching for the selected approved candidate; require verified destinations', 'type': 'boolean', 'default': False})
        env = workflow['jobs']['publish']['env']
        self.assertIn('inputs.metadata_batch_trial', env[FLAG])
        self.assertIn('inputs.metadata_batch_trial', env['PUBLICATION_REQUIRE_VERIFIED'])
        self.assertIn('inputs.readonly_preflight_trial', env['PUBLICATION_REQUIRE_VERIFIED'])
        steps = workflow['jobs']['publish']['steps']
        names = [step.get('name') for step in steps]
        self.assertLess(names.index('Inspect current public cache before closure materialization'), names.index('Restore authenticated qualified Nix closures without builders'))
        self.assertFalse(any('flakehub' in json.dumps(step).lower() for step in steps))
        for destination in ('cache',):
            with self.subTest(destination=destination), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                product = directory / 'product.json'
                product.write_text(json.dumps(self.product))
                stub = directory / 'inspect.py'
                stub.write_text('import destinations\n'
                    'destinations.cache = lambda *a, **k: {"schema":1,"destination":"cache","status":"partial","expected":{},"observed":{}}\n'
                    'destinations.main()\n')
                output = directory / 'github-output'
                result = subprocess.run(['bash', str(ROOT / 'nix/automation/publication-inspect.sh')],
                    env=dict(os.environ, PYTHONPATH=str(ROOT / 'nix/automation/decisions'),
                        PUBLICATION_DESTINATIONS_SOURCE=str(stub), DECISION_PRODUCT=str(product),
                        PUBLICATION_DESTINATION=destination, PUBLICATION_REQUIRE_VERIFIED='true',
                        PUBLICATION_PURPOSE='release', RELEASE_TAG='v1.2.3', GITHUB_OUTPUT=str(output)),
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stdout.strip(), result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'], 'partial')
                self.assertFalse(output.exists())

    def test_rotated_packet_retains_full_original_product_binding_in_both_modes(self):
        original = self.registry()
        self.scan['producer'] = dict(self.producer, runId=8)
        fresh = self.registry()
        for enabled in ('false', 'true'):
            with patch.dict(os.environ, {FLAG: enabled}), patch.object(mod, 'command', side_effect=self.transport(original, fresh)) as command:
                result = fetch.handoff_documents(self.policy(original), self.policy(fresh), 'xo-latest')
                self.assertEqual(result, self.data())
                self.assertEqual(command.call_count, 12 if enabled == 'false' else 8)
            self.product['roots']['other'] = {'changed': True}
            changed = self.registry()
            with patch.dict(os.environ, {FLAG: enabled}), patch.object(mod, 'command', side_effect=self.transport(original, changed)), self.assertRaisesRegex(ValueError, 'immutable upstream product'):
                fetch.handoff_documents(self.policy(original), self.policy(changed), 'xo-latest')
            self.product['roots'].clear()

    def test_expiry_revocation_and_malformed_metadata_still_reach_native_boundaries(self):
        for enabled in ('false', 'true'):
            for failure in ('expiry', 'revocation', 'malformed'):
                with self.subTest(enabled=enabled, failure=failure), tempfile.TemporaryDirectory() as temp:
                    data = self.data()
                    if failure == 'expiry':
                        scan = copy.deepcopy(self.scan)
                        scan['expiresAt'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()
                        envelope = json.loads(data[NAMES[2]])
                        envelope['scans'] = scan
                        data['scans.json'] = json.dumps(scan).encode()
                        data[NAMES[2]] = json.dumps(envelope).encode()
                    if failure == 'malformed':
                        data['scans.json'] = b'{'  # Integrity-valid bytes remain subject to the native JSON boundary.
                    registry = self.registry(data)
                    with patch.dict(os.environ, {FLAG: enabled}), patch.object(mod, 'command', side_effect=self.transport(registry)):
                        documents = fetch.handoff_documents(self.policy(registry), self.policy(registry), 'xo-latest')
                    directory = Path(temp)
                    for name, raw in documents.items():
                        (directory / name).write_bytes(raw)
                    cfg = {'repository': self.product['repository'], 'profiles': ['xo-latest']}
                    def gate(config, path, *args):
                        if failure == 'revocation':
                            raise common.authority.HumanDecisionRequired('Approval withdrawn')
                        return common.scans(path, config)
                    argv = ['handoff', '--config', 'unused', '--handoff', str(directory / NAMES[2]), '--directory', temp,
                            '--expected-revision', self.product['revision'], '--expected-channel', 'xo-latest',
                            '--expected-store-path', self.identity['storePath'], '--expected-nar-hash', self.identity['narHash']]
                    with patch.object(sys, 'argv', argv), patch.object(native_handoff, 'config', return_value=cfg), \
                         patch.object(common, 'attest_product'), patch.object(native_handoff, 'gate', side_effect=gate) as authority, self.assertRaises(ValueError):
                        native_handoff.main()
                    self.assertEqual(authority.call_count, int(failure != 'malformed'))

    def test_nonlogged_proof_records_actual_metadata_hashes_and_operation_counts(self):
        registry = self.registry()
        for enabled in ('false', 'true'):
            with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {FLAG: enabled, 'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp}), \
                 patch.dict(common.diagnostics.PROFILES, {}, clear=True), patch.object(mod, 'command', side_effect=self.transport(registry)):
                fetch.handoff_documents(self.policy(registry), self.policy(registry), 'xo-latest')
                path = next((Path(temp) / 'publication-diagnostics/objects').glob('*.result.json'))
                proof = json.loads(path.read_text())
                self.assertEqual(proof['members'], {name: sha(raw) for name, raw in self.data().items()})
                self.assertEqual(sum(proof['operationCounts'].values()), 9 if enabled == 'false' else 5)
                self.assertFalse(proof['authorityClaim'])

    def test_extreme_future_database_still_has_original_health_failure(self):
        scan = copy.deepcopy(self.scan)
        scan['profiles']['xo-latest']['database']['built'] = '9999-12-31T23:59:59Z'
        with tempfile.TemporaryDirectory() as temp, patch.object(common, 'verify_producer', return_value=('a' * 40, '.github/workflows/ci.yml')), patch.object(common, 'attest'):
            path = Path(temp) / 'scans.json'
            path.write_text(json.dumps(scan))
            with self.assertRaisesRegex(ValueError, 'database is stale'):
                common.scans(path, {'repository': self.product['repository'], 'profiles': ['xo-latest']})


if __name__ == '__main__':
    unittest.main()
