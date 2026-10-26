# SPDX-License-Identifier: Apache-2.0
"""Authenticated metadata reuse avoids fetches without caching authority."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from test_packets import Registry, mod, sha

FLAG = 'MAESTRO_PACKET_METADATA_REUSE_ENABLED'


class MetadataReuse(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        env = patch.dict(os.environ, {FLAG: 'true', 'MAESTRO_CI_DIAGNOSTICS': 'false', 'RUNNER_TEMP': self.temporary.name,
                                     'GITHUB_RUN_ID': '7', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'publish'})
        env.start()
        self.addCleanup(env.stop)
        self.registry = Registry()
        self.data = {'product.json': b'{"product":1}', 'scans.json': b'{"scan":2}',
                     'inputs.sha256': b'input digest', 'closure.tar.part-000': b'never downloaded'}
        r = self.registry
        r.packet = {'schema': 1, 'producer': {'runId': 7},
                    'files': {k: {'size': len(v), 'sha256': sha(v)} for k, v in self.data.items()}}
        self.refresh()
        self.command = patch.object(mod, 'command', side_effect=r.command)
        self.transport = self.command.start()
        self.addCleanup(self.command.stop)

    def refresh(self):
        r = self.registry
        r.packet_bytes = json.dumps(r.packet).encode()
        r.manifest['layers'] = [r.layer('decision-packet.json', r.packet_bytes)] + [
            {'annotations': {'org.opencontainers.image.title': name},
             'digest': 'sha256:' + record['sha256'], 'size': record['size']}
            for name, record in r.packet['files'].items()]
        r.blobs = {sha(v): v for v in self.data.values()}
        r.blobs[sha(r.packet_bytes)] = r.packet_bytes
        r.refresh()
        self.expected = mod.canonical_hash(r.packet)

    def read(self, name='product.json', producer=None):
        return mod.metadata_bytes(self.registry.reference, self.expected, name, producer)

    def cache(self):
        return mod.job_cache(self.registry.reference, self.expected) / 'metadata'

    def test_repeated_reads_return_identical_bytes_without_registry(self):
        self.assertEqual(self.read(), self.data['product.json'])
        self.assertEqual(self.transport.call_count, 3)
        self.assertEqual(mod.metadata(self.registry.reference, self.expected, 'product.json'), {'product': 1})
        self.assertEqual(self.transport.call_count, 3)
        self.assertEqual(self.read('inputs.sha256'), self.data['inputs.sha256'])
        self.assertEqual(self.transport.call_count, 4)
        result = mod.metadata_many(self.registry.reference, self.expected, ['product.json', 'scans.json'])
        self.assertEqual(result, {k: self.data[k] for k in ('product.json', 'scans.json')})
        self.assertEqual(self.transport.call_count, 5)
        self.assertFalse(any(sha(self.data['closure.tar.part-000']) in str(call) for call in self.transport.call_args_list))

    def test_disabled_and_incomplete_job_scope_do_not_reuse(self):
        for env in ({FLAG: 'false'}, {'GITHUB_JOB': ''}):
            self.transport.reset_mock()
            with patch.dict(os.environ, env):
                self.read(); self.read()
            self.assertEqual(self.transport.call_count, 6)

    def test_different_run_attempt_and_job_are_isolated(self):
        self.read()
        for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB'):
            before = self.transport.call_count
            with patch.dict(os.environ, {key: 'other'}):
                self.read()
            self.assertEqual(self.transport.call_count - before, 3)

    def test_registry_and_verifier_are_part_of_the_cache_binding(self):
        self.read()
        with patch.object(mod, 'verifier_version', return_value='different-verifier'):
            self.read()
        self.assertEqual(self.transport.call_count, 6)
        with patch.object(mod, 'REGISTRY', 'ghcr.io/closure-labs/other-decisions'), \
                patch.object(mod, 'REFERENCE', re.compile(r'ghcr.io/closure-labs/other-decisions@sha256:[0-9a-f]{64}')):
            self.registry.refresh()
            self.read()
        self.assertEqual(self.transport.call_count, 9)

    def test_hits_report_verified_bytes_and_logical_commands_avoided(self):
        self.read()
        with patch.dict(os.environ, {'MAESTRO_CI_DIAGNOSTICS': 'true'}), \
                patch.dict(mod.diagnostics.COUNTERS, {}, clear=True):
            self.read()
            counts = mod.diagnostics.COUNTERS
            self.assertEqual(counts['metadataCacheHits'], 3)
            self.assertEqual(counts['metadataRegistryOperationsAvoided'], 3)
            self.assertEqual(counts['metadataBytesReused'], len(self.registry.raw) +
                             len(self.registry.packet_bytes) + len(self.data['product.json']))

    def test_corruption_and_symlinks_fail_without_registry_fallback(self):
        self.read()
        target = self.cache() / sha(self.data['product.json'])
        for kind in ('corrupt', 'symlink', 'fifo'):
            if target.exists() or target.is_symlink(): target.unlink()
            if kind == 'corrupt': target.write_bytes(b'corrupt')
            elif kind == 'symlink': target.symlink_to('/dev/null')
            else: os.mkfifo(target)
            before = self.transport.call_count
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.read()
            self.assertEqual(self.transport.call_count, before)

    def test_symlinked_cache_ancestor_rejected(self):
        root = Path(self.temporary.name) / 'decision-packet-cache'
        root.symlink_to(Path(self.temporary.name), target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Unsafe'): self.read()
        self.transport.assert_not_called()

    def test_missing_cached_member_fetches_only_that_member(self):
        self.read()
        (self.cache() / sha(self.data['product.json'])).unlink()
        self.read()
        self.assertEqual(self.transport.call_count, 4)

    def test_cached_producer_and_descriptor_bindings_revalidated(self):
        self.read()
        with self.assertRaisesRegex(ValueError, 'producer differs'):
            self.read(producer={'runId': 8})
        self.assertEqual(self.transport.call_count, 3)
        self.expected = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'approved manifest'): self.read()

    def test_oversized_missing_and_payload_members_never_fetched(self):
        self.registry.packet['files']['product.json']['size'] = 16 * 1024**2 + 1
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'oversized'): self.read()
        self.assertEqual(self.transport.call_count, 1)
        with self.assertRaisesRegex(ValueError, 'absent'): self.read('missing.json')
        with self.assertRaisesRegex(ValueError, 'closure payloads'): self.read('closure.tar.part-000')
        self.assertEqual(self.transport.call_count, 1)

    def test_unavailable_transport_is_not_changed_into_integrity_failure(self):
        self.read()
        self.transport.side_effect = mod.RegistryUnavailable('transport unavailable')
        self.assertEqual(self.read(), self.data['product.json'])
        with self.assertRaises(mod.RegistryUnavailable): self.read('scans.json')

    def test_concurrent_writers_publish_only_complete_verified_bytes(self):
        with ThreadPoolExecutor(max_workers=4) as workers:
            results = list(workers.map(lambda _: self.read(), range(8)))
        self.assertTrue(all(value == self.data['product.json'] for value in results))
        before = self.transport.call_count
        self.read()
        self.assertEqual(self.transport.call_count, before)
        self.assertFalse(list(self.cache().glob('.metadata-*')))

    def test_hit_does_not_extend_deadline(self):
        self.read()
        with mod.operations.budget(.001):
            time.sleep(.005)
            with self.assertRaises(subprocess.TimeoutExpired): self.read()

    def test_corrupt_manifest_and_descriptor_fail_closed(self):
        self.read()
        for digest in (sha(self.registry.raw), sha(self.registry.packet_bytes)):
            path = self.cache() / digest
            original = path.read_bytes()
            path.write_bytes(b'bad')
            with self.assertRaises(ValueError): self.read()
            path.write_bytes(original)
        self.assertEqual(self.transport.call_count, 3)


if __name__ == '__main__':
    unittest.main()
