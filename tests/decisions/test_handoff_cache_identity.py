# SPDX-License-Identifier: Apache-2.0
"""Metadata-only handoff checks use the already pinned public cache set."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

AUTOMATION = Path(__file__).resolve().parents[2] / 'nix/automation'
sys.path.insert(0, str(AUTOMATION / 'decisions'))
spec = importlib.util.spec_from_file_location('handoff_cache_identity', AUTOMATION / 'decision-handoff-fetch.py')
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)
import destinations

STORE = '/nix/store/7rgckrz7zf9l3rvidb4987gcxgi07a8i-xen-orchestra-ce-6.9.1'
HASH = 'sha256-xc1ppaaqEWgTOuKmIg/0+3mj8cd4BEmuncuJYx/+GfI='
MAESTRO = 'https://maestro.cachix.org'
XO = 'https://xen-orchestra-ce.cachix.org'
NIXOS = 'https://cache.nixos.org'


def narinfo(**changes):
    fields = {'StorePath': STORE, 'URL': 'nar/fixture.nar.zst', 'NarSize': '123', 'NarHash': HASH}
    fields.update(changes)
    return ''.join(name + ': ' + value + '\n' for name, value in fields.items()).encode()


class HandoffCacheIdentity(unittest.TestCase):
    def invoke(self, responses, *, local=False, local_records=None):
        context = ({'runtime': {'xoPackage': STORE}},
                   [{'properties': [{'name': 'nix:storePath', 'value': STORE}]}])
        calls = []
        def read(url, **kwargs):
            calls.append(url)
            return responses[len(calls) - 1]
        with patch.object(handoff, 'runtime_context', return_value=context), \
                patch.object(handoff.Path, 'exists', return_value=local), \
                patch.object(destinations, 'http', side_effect=read), \
                patch.object(handoff.common, 'command',
                             return_value=json.dumps(local_records)) as command:
            if not local:
                command.side_effect = AssertionError('Metadata-only lookup started Nix')
            try:
                result = handoff.actual_output(Path('/verified-inventory'))
            finally:
                if not local:
                    command.assert_not_called()
        return result, calls, command

    def test_local_output_retains_native_nix_identity_query(self):
        for records in ({STORE: {'narHash': HASH}}, [{'path': STORE, 'narHash': HASH}]):
            with self.subTest(records=records):
                result, calls, command = self.invoke([], local=True, local_records=records)
                self.assertEqual(result, {'storePath': STORE, 'narHash': HASH})
                self.assertEqual(calls, [])
                command.assert_called_once_with(['nix', 'path-info', '--json', STORE], timeout=120)

    def test_primary_cache_match_needs_no_upstream_or_closure(self):
        result, calls, _ = self.invoke([(200, narinfo())])
        self.assertEqual(result, {'storePath': STORE, 'narHash': HASH})
        self.assertEqual(calls, [MAESTRO + '/' + Path(STORE).name[:32] + '.narinfo'])

    def test_live_upstream_only_layout_falls_back_on_404(self):
        result, calls, _ = self.invoke([(404, b''), (200, narinfo())])
        self.assertEqual(result, {'storePath': STORE, 'narHash': HASH})
        self.assertEqual([url.split('/')[2] for url in calls], ['maestro.cachix.org', 'xen-orchestra-ce.cachix.org'])

    def test_nixos_is_the_only_other_permitted_fallback(self):
        result, calls, _ = self.invoke([(404, b''), (404, b''), (200, narinfo())])
        self.assertEqual(result['narHash'], HASH)
        self.assertEqual([url.rsplit('/', 1)[0] for url in calls], [MAESTRO, XO, NIXOS])

    def test_all_missing_blocks(self):
        with self.assertRaises(ValueError):
            self.invoke([(404, b''), (404, b''), (404, b'')])

    def test_unavailable_or_denied_is_not_treated_as_a_cache_miss(self):
        for status in (None, 301, 401, 403, 429, 500, 503):
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.invoke([(status, b''), (200, narinfo())])

    def test_malformed_metadata_blocks_before_any_fallback(self):
        bodies = [narinfo(StorePath=STORE + '-other'), narinfo(NarHash='not-a-hash'),
                  narinfo(NarSize='0'), narinfo(URL=''), b'not narinfo\n',
                  narinfo() + b'NarHash: ' + HASH.encode() + b'\n']
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.invoke([(200, body), (200, narinfo())])

    def test_first_observed_hash_is_not_replaced_by_a_matching_upstream(self):
        other = 'sha256-' + 'A' * 43 + '='
        result, calls, _ = self.invoke([(200, narinfo(NarHash=other)), (200, narinfo())])
        self.assertEqual(result['narHash'], other)
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(result['narHash'], HASH, 'The existing exact policy comparison must reject this')

    def test_nix_base32_hash_is_normalized_to_the_existing_policy_format(self):
        result, _, _ = self.invoke([(404, b''), (200, narinfo(
            NarHash='sha256:1whrzqgn72fbknp4j13qqzqs6ygvyh7j59p2789nh4dalsjnkkf5'))])
        self.assertEqual(result['narHash'], HASH)

    def test_conflicting_remote_hash_blocks_before_upstream_credentials_or_packets(self):
        policy = {'schema': 1, 'mode': 'official', 'repository': 'closure-labs/xo-nixpkg',
                  'revision': 'e' * 40, 'channel': 'xo-latest', 'storePath': STORE, 'narHash': HASH}
        context = ({'runtime': {'xoPackage': STORE}},
                   [{'properties': [{'name': 'nix:storePath', 'value': STORE}]}])
        env = {'MAESTRO_SYSTEM_ROOT': '/fixture', 'DECISION_EVIDENCE_DIRECTORY': '/retained',
               'GH_TOKEN': 'fixture-downstream', 'XO_AUTHORITY_TOKEN': 'fixture-upstream'}
        with patch.dict(os.environ, env), \
                patch.object(handoff.common, 'config', return_value={'repository': 'closure-labs/maestro'}), \
                patch.object(handoff.common, 'scans', return_value={}), \
                patch.object(handoff.common, 'product', return_value={'revision': 'a' * 40}), \
                patch.object(handoff.common, 'main_revision', return_value='c' * 40), \
                patch.object(handoff, 'load_json', return_value=policy), \
                patch.object(handoff, 'document_at', return_value=policy), \
                patch.object(handoff, 'locked_revision', return_value='e' * 40), \
                patch.object(handoff, 'expected_channel', return_value='xo-latest'), \
                patch.object(handoff, 'runtime_context', return_value=context), \
                patch.object(handoff.Path, 'exists', return_value=False), \
                patch.object(destinations, 'http', return_value=(200, narinfo(NarHash='sha256-' + 'A' * 43 + '='))), \
                patch.object(handoff.common, 'command') as command, \
                patch.object(handoff.packets, 'metadata_bytes') as metadata:
            with self.assertRaisesRegex(ValueError, 'Handoff policy differs'):
                handoff.main()
            self.assertEqual(os.environ['GH_TOKEN'], 'fixture-downstream')
            command.assert_not_called()
            metadata.assert_not_called()

    def test_duplicate_signatures_preserve_valid_metadata(self):
        result, _, _ = self.invoke([(200, narinfo() + b'Sig: first\nSig: second\n')])
        self.assertEqual(result['narHash'], HASH)


if __name__ == '__main__':
    unittest.main()
