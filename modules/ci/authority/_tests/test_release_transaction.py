# SPDX-License-Identifier: Apache-2.0
"""Fresh authority per write group, including uncertain-outcome recovery."""
import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('completion', ROOT / 'modules/ci/authority/_source/release-completion.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
SHA = 'a' * 40
TAG = 'v1.2.3'
REPO = 'owner/repo'


class API:
    def __init__(self):
        self.branch = False
        self.document = None
        self.tag = None
        self.release = None
        self.remote = {}
        self.bytes = {}
        self.events = []
        self.fail = None
        self.revoke = False

    def authorize(self):
        self.events.append('authorize')
        if self.revoke: raise ValueError('revoked')

    def __call__(self, endpoint, method='GET', payload=None):
        self.events.append((method, endpoint))
        if method != 'GET' and self.fail == 'conflict' and method == 'PUT':
            self.fail = None
            raise mod.journal.GitHubError(409, 'journal conflict')
        result = self.apply(endpoint, method, payload)
        if method != 'GET' and self.fail == 'lost-ack':
            self.fail = None
            raise mod.journal.GitHubError(503, 'lost acknowledgement')
        return deepcopy(result)

    def apply(self, endpoint, method, payload):
        if endpoint.endswith('/git/ref/heads/main'): return {'object': {'sha': SHA}}
        if endpoint.endswith('/git/ref/heads/' + mod.journal.BRANCH):
            if not self.branch: raise mod.journal.GitHubError(404, 'missing')
            return {'ref': 'refs/heads/' + mod.journal.BRANCH, 'object': {'sha': SHA}}
        if '/git/ref/tags/' in endpoint:
            if self.tag is None: raise mod.journal.GitHubError(404, 'missing')
            return {'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': self.tag}}
        if endpoint.endswith('/git/refs'):
            if payload['ref'].startswith('refs/heads/'): self.branch = True
            else: self.tag = payload['sha']
            return {}
        if '/contents/publications/' in endpoint:
            if method == 'PUT':
                self.document = json.loads(base64.b64decode(payload['content']))
            if self.document is None: raise mod.journal.GitHubError(404, 'missing')
            return {'type': 'file', 'encoding': 'base64', 'sha': 'b' * 40,
                    'content': base64.b64encode(json.dumps(self.document).encode()).decode()}
        if '/releases?per_page=' in endpoint: return [self.release] if self.release else []
        if endpoint.endswith('/releases'):
            self.release = {'id': 5, **payload}
            return self.release
        if '/releases/5/assets?' in endpoint: return list(self.remote.values())
        if endpoint.endswith('/releases/5'):
            if method == 'PATCH': self.release.update(payload)
            return self.release
        raise AssertionError(endpoint)

    def upload(self, repository, tag, paths):
        self.events.append('upload')
        for path in paths:
            assert path.name not in self.remote
            self.bytes[path.name] = path.read_bytes()
            self.remote[path.name] = {'id': len(self.remote) + 1, 'name': path.name,
                                      'size': path.stat().st_size, 'state': 'uploaded'}

    def download(self, repository, asset):
        self.events.append('download:' + asset['name'])
        return hashlib.sha256(self.bytes[asset['name']]).hexdigest()


class Transaction(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        values = {'release-notes.md': b'reviewed notes', 'asset.iso': b'approved bytes'}
        for name, raw in values.items(): (self.directory / name).write_bytes(raw)
        self.product = {'schema': 1, 'repository': REPO, 'revision': SHA,
                        'assets': {k: hashlib.sha256(v).hexdigest() for k, v in values.items()}}
        self.api = API()

    def reserve(self):
        return mod.reserve(REPO, self.product, self.directory, TAG, SHA, self.api.authorize, self.api)

    def stage(self, send=None):
        return mod.assets.reconcile(REPO, self.product, self.directory, TAG, SHA, False,
                                    self.api.authorize, self.api, self.api.download, send or self.api.upload, stage_only=True)

    def complete(self):
        return mod.complete(REPO, self.product, self.directory, TAG, SHA,
                            self.api.authorize, self.api, self.api.download)

    def test_each_group_has_exactly_one_fresh_authorization_and_receipt(self):
        self.reserve()
        self.assertEqual(self.api.events.count('authorize'), 1)
        self.stage()
        self.assertEqual(self.api.events.count('authorize'), 2)
        self.assertTrue(self.api.release['draft'])
        result, receipt = self.complete()
        self.assertEqual(self.api.events.count('authorize'), 3)
        self.assertFalse(self.api.release['draft'])
        self.assertEqual(result['status'], 'published')
        self.assertEqual(self.api.document['receipts']['github'], receipt)
        self.assertEqual(self.api.document['steps']['github'], 'complete')
        last_auth = len(self.api.events) - 1 - self.api.events[::-1].index('authorize')
        downloads = [i for i, e in enumerate(self.api.events) if isinstance(e, str) and e.startswith('download:')]
        self.assertTrue(downloads and max(downloads) < last_auth)
        original = deepcopy(self.api.document)
        self.complete()
        self.assertEqual(self.api.document, original)
        self.assertEqual(self.api.events.count('authorize'), 4)

    def test_revocation_between_groups_prevents_next_mutation(self):
        for boundary in ('asset', 'completion'):
            self.setUp()
            self.reserve()
            if boundary == 'completion': self.stage()
            self.api.revoke = True
            before = deepcopy((self.api.document, self.api.release, self.api.remote))
            with self.subTest(boundary=boundary), self.assertRaisesRegex(ValueError, 'revoked'):
                self.stage() if boundary == 'asset' else self.complete()
            self.assertEqual((self.api.document, self.api.release, self.api.remote), before)

    def test_upstream_rejection_after_downstream_success_prevents_group_writes(self):
        product_path = self.directory / 'product.json'
        product_path.write_text(json.dumps(self.product))
        for phase in ('reserve', 'complete'):
            if phase == 'complete':
                self.reserve()
                self.stage()
            before = deepcopy((self.api.document, self.api.release, self.api.remote))
            operation = getattr(mod, phase)
            def execute(*args):
                return operation(*args, github=self.api,
                                 **({'download': self.api.download} if phase == 'complete' else {}))
            argv = ['release-completion', '--config', 'unused', '--product', str(product_path), '--scans', 'unused',
                    '--directory', str(self.directory), '--tag', TAG, '--revision', SHA]
            if phase == 'reserve': argv.append('--reserve')
            with self.subTest(phase=phase), patch.object(sys, 'argv', argv), \
                    patch.object(mod.common, 'config', return_value={'repository': REPO}), \
                    patch.object(mod.common, 'gate', return_value={'productHash': mod.common.canonical_hash(self.product)}) as gate, \
                    patch.object(mod.common, 'command', side_effect=ValueError('upstream binding changed')) as handoff, \
                    patch.object(mod, phase, side_effect=execute):
                with self.assertRaisesRegex(ValueError, 'upstream binding changed'):
                    mod.main()
                gate.assert_called_once()
                handoff.assert_called_once_with(['maestro-ci-decision-handoff'])
            self.assertEqual((self.api.document, self.api.release, self.api.remote), before)

    def test_noop_journal_change_during_authority_blocks_reservation_writes(self):
        self.api.branch = True
        self.api.document = {'schema': 1, 'productHash': mod.common.canonical_hash(self.product),
                             'steps': {'github': 'pending'}}
        def authorize():
            self.api.authorize()
            self.api.document['productHash'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'journal readback differs'):
            mod.reserve(REPO, self.product, self.directory, TAG, SHA, authorize, self.api)
        self.assertIsNone(self.api.tag)
        self.assertIsNone(self.api.release)
        self.assertFalse(any(isinstance(event, tuple) and event[0] != 'GET' for event in self.api.events))

    def test_conflict_and_lost_ack_stop_then_readback_before_fresh_retry(self):
        for failure in ('conflict', 'lost-ack'):
            self.setUp()
            self.api.fail = failure
            with self.subTest(failure=failure), self.assertRaises(mod.journal.GitHubError): self.reserve()
            self.assertEqual(self.api.events.count('authorize'), 1)
            self.assertIsNone(self.api.release)
            self.assertEqual(self.api.events[-1][0], 'GET')
            self.reserve()
            self.assertEqual(self.api.events.count('authorize'), 2)
            self.assertIsNotNone(self.api.release)

    def test_completion_journal_conflict_leaves_published_bytes_and_requires_fresh_retry(self):
        self.reserve(); self.stage()
        self.api.fail = 'conflict'
        with self.assertRaises(mod.journal.GitHubError): self.complete()
        self.assertFalse(self.api.release['draft'])
        self.assertEqual(self.api.document['steps']['github'], 'pending')
        self.assertEqual(self.api.events[-1][0], 'GET')
        before = self.api.events.count('authorize')
        self.complete()
        self.assertEqual(self.api.events.count('authorize'), before + 1)
        self.assertEqual(self.api.document['steps']['github'], 'complete')

    def test_lost_publication_ack_does_not_write_receipt_before_fresh_retry(self):
        self.reserve(); self.stage()
        self.api.fail = 'lost-ack'
        with self.assertRaises(mod.journal.GitHubError): self.complete()
        self.assertFalse(self.api.release['draft'])
        self.assertEqual(self.api.document['steps']['github'], 'pending')
        before = self.api.events.count('authorize')
        self.complete()
        self.assertEqual(self.api.events.count('authorize'), before + 1)
        self.assertEqual(self.api.document['steps']['github'], 'complete')

    def test_tag_changed_during_authorization_blocks_publication(self):
        self.reserve(); self.stage()
        def changed():
            self.api.events.append('authorize')
            self.api.tag = 'f' * 40
        self.api.authorize = changed
        with self.assertRaisesRegex(ValueError, 'tag changed'): self.complete()
        self.assertTrue(self.api.release['draft'])
        self.assertEqual(self.api.document['steps']['github'], 'pending')

    def test_interrupted_upload_resumes_missing_only_and_keeps_both_readbacks(self):
        self.reserve()
        def interrupted(repository, tag, paths):
            self.api.upload(repository, tag, paths[:1])
            raise OSError('interrupted')
        with self.assertRaises(OSError): self.stage(interrupted)
        first = next(iter(self.api.remote))
        self.stage()
        self.complete()
        self.assertEqual(self.api.events.count('download:' + first), 2)
        self.assertEqual(set(self.api.remote), set(self.product['assets']))

    def test_tag_conflict_and_tampered_hosted_bytes_block(self):
        self.api.tag = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'another source'): self.reserve()
        self.assertNotIn('authorize', self.api.events)
        self.api.tag = None
        self.reserve(); self.stage()
        self.api.bytes['asset.iso'] = b'tampered'
        before = self.api.events.count('authorize')
        with self.assertRaisesRegex(ValueError, 'Hosted bytes differ'): self.complete()
        self.assertEqual(self.api.events.count('authorize'), before)
        self.assertTrue(self.api.release['draft'])

    def test_new_stage_diagnostics_keep_producer_identity_and_bounded_labels(self):
        digest = mod.common.canonical_hash(self.product)
        d = mod.common.diagnostics
        for phase, argv in [('release-reservation', ['--reserve']), ('release-completion', [])]:
            with patch.dict(os.environ, {'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': self.temporary.name}), \
                    patch.object(sys, 'argv', ['/nix/store/' + 'a' * 32 + '-release-completion.py', *argv]):
                d.record({'status': 'covered', 'productHash': digest,
                          'producer': {'revision': SHA, 'runId': 7, 'runAttempt': 1}}, 'gate', logged=False)
                raw = d.record({'status': 'published', 'productHash': digest})
                result = json.loads(raw)
                self.assertEqual(result['kind'], phase)
                self.assertEqual(result['producerRun'], 7)
                self.assertLessEqual(len(raw.encode()), 4096)

    def test_verified_trial_preserves_both_readbacks_and_fresh_authority(self):
        self.reserve(); self.stage(); self.complete()
        before = deepcopy((self.api.document, self.api.release, self.api.remote))
        self.api.events.clear()
        with patch.dict(os.environ, {'PUBLICATION_REQUIRE_VERIFIED': 'true'}):
            self.reserve(); self.stage()
            result, receipt = self.complete()
        self.assertEqual(result['status'], 'published')
        self.assertEqual(receipt['expected'], self.api.document['receipts']['github']['expected'])
        self.assertEqual((self.api.document, self.api.release, self.api.remote), before)
        self.assertEqual(self.api.events.count('authorize'), 2)
        for name in self.product['assets']:
            self.assertEqual(self.api.events.count('download:' + name), 2)
        self.assertNotIn('upload', self.api.events)
        self.assertFalse(any(isinstance(e, tuple) and e[0] != 'GET' for e in self.api.events))

    def test_verified_trial_rejects_missing_destinations_without_mutation(self):
        for missing in ('tag', 'release', 'draft', 'asset', 'journal'):
            self.setUp()
            self.reserve(); self.stage(); self.complete()
            if missing == 'tag': self.api.tag = None
            elif missing == 'release': self.api.release = None
            elif missing == 'draft': self.api.release['draft'] = True
            elif missing == 'asset': self.api.remote.pop('asset.iso')
            else: self.api.document = None
            before = deepcopy((self.api.document, self.api.release, self.api.remote))
            self.api.events.clear()
            with self.subTest(missing=missing), patch.dict(os.environ, {'PUBLICATION_REQUIRE_VERIFIED': 'true'}):
                with self.assertRaisesRegex(ValueError, 'Verified-only|incomplete'):
                    self.reserve(); self.stage(); self.complete()
            self.assertEqual((self.api.document, self.api.release, self.api.remote), before)
            self.assertNotIn('upload', self.api.events)
            self.assertFalse(any(isinstance(e, tuple) and e[0] != 'GET' for e in self.api.events))

    def test_verified_trial_blocks_leaf_upload_and_api_mutations(self):
        with patch.dict(os.environ, {'PUBLICATION_REQUIRE_VERIFIED': 'true'}), \
                patch.object(mod.assets.subprocess, 'run') as command:
            for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                with self.subTest(method=method), self.assertRaisesRegex(ValueError, 'forbids GitHub mutations'):
                    mod.journal.api('repos/owner/repo/releases', method, {})
            with self.assertRaisesRegex(ValueError, 'forbids asset uploads'):
                mod.assets.upload(REPO, TAG, [self.directory / 'asset.iso'])
            command.assert_not_called()

    def test_verified_trial_legacy_path_retains_authority_and_readbacks(self):
        self.reserve(); self.stage(); self.complete()
        self.api.events.clear()
        with patch.dict(os.environ, {'PUBLICATION_REQUIRE_VERIFIED': 'true'}):
            result = mod.assets.reconcile(REPO, self.product, self.directory, TAG, SHA, True,
                                         self.api.authorize, self.api, self.api.download, self.api.upload)
        self.assertEqual(result['status'], 'published')
        self.assertEqual(self.api.events.count('authorize'), 1)
        for name in self.product['assets']:
            self.assertEqual(self.api.events.count('download:' + name), 2)
        self.assertFalse(any(isinstance(e, tuple) and e[0] != 'GET' for e in self.api.events))

    def test_verified_trial_rejects_receipt_update_and_draft_completion(self):
        self.reserve(); self.stage()
        with patch.dict(os.environ, {'PUBLICATION_REQUIRE_VERIFIED': 'true'}):
            with self.assertRaisesRegex(ValueError, 'published release'): self.complete()
        self.assertTrue(self.api.release['draft'])
        self.api.release['draft'] = False
        with patch.dict(os.environ, {'PUBLICATION_REQUIRE_VERIFIED': 'true'}):
            with self.assertRaisesRegex(ValueError, 'unchanged journal'): self.complete()
        self.assertEqual(self.api.document['steps']['github'], 'pending')

    def test_asset_stage_requires_prior_reservation(self):
        with self.assertRaisesRegex(ValueError, 'reserved tag'): self.stage()
        self.assertNotIn('authorize', self.api.events)


if __name__ == '__main__': unittest.main()
