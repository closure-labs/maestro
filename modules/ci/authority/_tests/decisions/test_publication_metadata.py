# SPDX-License-Identifier: Apache-2.0
"""Admitted rolling publications inspect destinations before closure transfers."""
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[5]
AUTOMATION = ROOT / 'modules/ci/authority/_source'
sys.path.insert(0, str(AUTOMATION / 'decisions'))


def load(name):
    spec = importlib.util.spec_from_file_location('publication_' + name.replace('-', '_'),
                                                AUTOMATION / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


download = load('decision-download')
retained = load('decision-retained')


class PublicationMetadata(unittest.TestCase):
    def setUp(self):
        self.cfg = {'repository': 'closure-labs/maestro',
                    'producerWorkflows': ['.github/workflows/ci.yml', '.github/workflows/security.yml']}
        self.producer = dict(repository=self.cfg['repository'], revision='a' * 40,
                             sourceRevision='a' * 40, runId=123, runAttempt=1,
                             workflow='.github/workflows/ci.yml')
        self.product = dict(repository=self.cfg['repository'], revision='a' * 40,
                            products={}, roots={}, assets={})
        self.proposal = {'kind': 'release-product', 'payload': {
            'disposition': 'accepted', 'rationale': 'Exact fixture product reviewed', 'supersedes': [],
            'product': self.product, 'packet': {
                'reference': retained.packets.REGISTRY + '@sha256:' + 'b' * 64,
                'sha256': 'c' * 64, 'producer': self.producer}}}
        self.digest = retained.canonical_hash(self.proposal)
        self.records = {self.digest: self.proposal}
        self.run = dict(id=123, run_attempt=1, head_sha='a' * 40, head_branch='main',
                        path='.github/workflows/ci.yml', status='completed', conclusion='success',
                        event='push', repository={'full_name': self.cfg['repository']})
        self.env = dict(PUBLICATION_METADATA_ONLY='true', PUBLICATION_PURPOSE='rolling',
                        CANDIDATE_RUN='123', CANDIDATE_WORKFLOW='.github/workflows/ci.yml')

    def select(self, records=None, run=None, identity='123', workflow='.github/workflows/ci.yml'):
        with patch.object(retained.authority, 'github_api', return_value=self.run if run is None else run) as api, \
                patch.object(retained.common, 'historical_provenance'), \
                patch.object(retained.common, 'authorize', side_effect=AssertionError('selection authorized')), \
                patch.object(retained.packets, 'fetch', side_effect=AssertionError('payload fetched')), \
                patch.object(retained.packets, 'metadata', side_effect=AssertionError('selection fetched metadata')):
            result = retained.rolling_publication_candidate(
                self.cfg, self.records if records is None else records, identity, workflow)
        api.assert_called_once_with('repos/closure-labs/maestro/actions/runs/123')
        return result

    def test_publication_delegates_before_actions_inventory_or_transport(self):
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(download, 'api', side_effect=AssertionError('Actions archive path reached')), \
                patch.object(download.operations, 'run', side_effect=AssertionError('transport reached')):
            with self.assertRaises(SystemExit) as caught:
                download.main()
        self.assertEqual(caught.exception.code, 3)

    def test_canonical_run_and_conflicting_release_selector_fail_before_transport(self):
        for value in ('0', '01', '123\n', 'x', '1' * 21):
            env = dict(self.env, CANDIDATE_RUN=value)
            with self.subTest(value=value), patch.dict(os.environ, env, clear=True), \
                    patch.object(download, 'api', side_effect=AssertionError('Actions reached')), \
                    self.assertRaises(ValueError):
                download.main()
        with patch.dict(os.environ, dict(self.env, CANDIDATE_RELEASE_ONLY='true'), clear=True), \
                self.assertRaises(ValueError):
            download.main()

    def test_nonpublication_and_official_fresh_candidate_routes_remain_available(self):
        class ActionsRead(Exception):
            pass
        for purpose in ('', 'release'):
            with self.subTest(purpose=purpose), \
                    patch.dict(os.environ, dict(self.env, PUBLICATION_PURPOSE=purpose), clear=True), \
                    patch.object(download, 'api', side_effect=ActionsRead) as api, \
                    self.assertRaises(ActionsRead):
                download.main()
            api.assert_called_once_with('actions/runs/123')

    def test_exact_current_admitted_producer_selects_data_without_authorizing(self):
        self.assertEqual(self.select(), (self.digest, self.proposal))

    def test_absent_rejected_revoked_superseded_or_official_products_block(self):
        cases = [{}]
        for disposition in ('rejected', 'revoked'):
            value = deepcopy(self.proposal)
            value['payload']['disposition'] = disposition
            cases.append({retained.canonical_hash(value): value})
        official = deepcopy(self.proposal)
        official['payload']['product']['assets'] = {'maestro-v1.2.3.iso.sha256': 'd' * 64}
        cases.append({retained.canonical_hash(official): official})
        newer = deepcopy(self.proposal)
        newer['payload'].update(supersedes=[self.digest], rationale='New exact review')
        newer['payload']['packet']['producer']['runId'] = 124
        cases.append(dict(self.records, **{retained.canonical_hash(newer): newer}))
        for records in cases:
            with self.subTest(records=list(records)), self.assertRaises(ValueError):
                self.select(records=records)

    def test_two_distinct_products_for_one_run_never_select_arbitrarily(self):
        other = deepcopy(self.proposal)
        other['payload']['product']['roots'] = {'other': {'storePath': '/nix/store/' + 'd' * 32 + '-other'}}
        with self.assertRaises(ValueError):
            self.select(records=dict(self.records, **{retained.canonical_hash(other): other}))

    def test_latest_run_and_attempt_must_still_match_the_admitted_packet(self):
        changes = [('id', True), ('id', 124), ('run_attempt', True), ('run_attempt', 0),
                   ('run_attempt', 2), ('head_sha', 'd' * 40), ('head_branch', 'proposal'),
                   ('path', '.github/workflows/other.yml'), ('status', 'in_progress'),
                   ('conclusion', 'failure'), ('event', 'pull_request'),
                   ('repository', {'full_name': 'foreign/repo'})]
        for key, value in changes:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.select(run=dict(self.run, **{key: value}))
        with self.assertRaises(ValueError):
            self.select(workflow='.github/workflows/security.yml')

    def test_every_packet_producer_binding_is_checked(self):
        for key, value in [('repository', 'foreign/repo'), ('workflow', '.github/workflows/security.yml'),
                           ('revision', 'd' * 40), ('sourceRevision', 'e' * 40),
                           ('runAttempt', True), ('runAttempt', 2), ('runId', True)]:
            value_proposal = deepcopy(self.proposal)
            value_proposal['payload']['packet']['producer'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.select(records={retained.canonical_hash(value_proposal): value_proposal})

    def test_malformed_latest_run_metadata_blocks_before_packet_reads(self):
        for value in ([{}], {}, dict(self.run, path=None), dict(self.run, repository=None)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.select(run=value)

    def invoke_reader(self, *, records=None, product=None, environment=None, arguments=()):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'evidence'
            argv = ['retained', '--config', 'unused', '--directory', str(directory), *arguments]
            scan = dict(revision=self.product['revision'], profiles={'maestro': {}},
                        producer={k: v for k, v in self.producer.items()
                                  if k not in ('repository', 'sourceRevision')})
            with patch.dict(os.environ, dict(self.env, **(environment or {})), clear=True), \
                    patch.object(sys, 'argv', argv), \
                    patch.object(retained.common, 'config', return_value=self.cfg), \
                    patch.object(retained.common, 'ledger', return_value=('f' * 40, self.records if records is None else records)), \
                    patch.object(retained.authority, 'github_api', return_value=self.run), \
                    patch.object(retained, 'pending', side_effect=AssertionError('pending proposal discovery reached')), \
                    patch.object(retained.authority, 'collection', side_effect=AssertionError('release discovery reached')), \
                    patch.object(retained.packets, 'fetch', side_effect=AssertionError('closure payload fetched')), \
                    patch.object(retained.packets, 'metadata', return_value={'producer': self.producer, 'files': {}}) as descriptor, \
                    patch.object(retained.packets, 'metadata_bytes', return_value=b'{}') as metadata, \
                    patch.object(retained.common, 'scans', return_value=scan) as scans, \
                    patch.object(retained.common, 'product', return_value=self.product if product is None else product) as products, \
                    patch.object(retained, 'verify_native_files') as verify_inputs, redirect_stdout(io.StringIO()) as output:
                retained.main()
            scans.assert_called_once()
            products.assert_called_once()
            verify_inputs.assert_called_once_with(directory, {})
            self.assertEqual(descriptor.call_args.args[2], 'decision-packet.json')
            self.assertEqual({call.args[2] for call in metadata.call_args_list},
                             {'scans.json', 'product.json', 'inputs.sha256', 'inventory/maestro-system.cdx.json',
                              'inventory/xen-orchestra-supply.cdx.json', 'inventory/Cargo.lock'})
            return json.loads(output.getvalue())

    def test_actual_reader_uses_only_metadata_and_retains_native_verifiers(self):
        result = self.invoke_reader()
        self.assertEqual(result['proposal_hash'], self.digest)
        self.assertEqual(result['candidate_run'], '123')
        self.assertEqual(result['release'], 'false')

    def test_missing_explicit_candidate_hard_blocks_even_when_optional(self):
        with self.assertRaises(ValueError):
            self.invoke_reader(records={}, arguments=['--optional'])

    def test_conflicting_environment_or_cli_selectors_hard_block(self):
        for environment, arguments in [({'CANDIDATE_RELEASE_ONLY': 'true'}, []),
                                       ({'DECISION_RELEASE_ONLY': 'true'}, []),
                                       ({'CANDIDATE_PROPOSAL_HASH': 'a' * 64}, []),
                                       ({}, ['--release-only']),
                                       ({}, ['--admitted-release']),
                                       ({}, ['--proposal-hash', 'a' * 64])]:
            with self.subTest(environment=environment, arguments=arguments), self.assertRaises(ValueError):
                self.invoke_reader(environment=environment, arguments=arguments)

    def test_metadata_product_must_still_equal_the_exact_approved_bytes(self):
        changed = dict(self.product, revision='d' * 40)
        with self.assertRaises(ValueError):
            self.invoke_reader(product=changed)


if __name__ == '__main__':
    unittest.main()
