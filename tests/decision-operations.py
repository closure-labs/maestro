#!/usr/bin/env python3
"""Operational boundary fixtures; no actual registry or GitHub writes."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'modules/ci/authority/_source/decisions'))


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'modules/ci/authority/_source' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


refresh = module('decision-refresh')
health = module('decision-health')
handoff = module('decision-handoff-fetch')
retained = module('decision-retained')


class Operations(unittest.TestCase):
    def test_publication_creates_report_parent_for_retained_candidate_and_preserves_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / 'controller'
            source.mkdir()
            # Exercise the real shell entry point and Python report writer;
            # isolate only remote policy/authority calls from this local test.
            (source / 'publication.py').write_text(
                'import os, runpy, sys\n'
                f'sys.path.insert(0, {str(ROOT / "modules/ci/authority/_source/decisions")!r})\n'
                'import common\n'
                'common.config = lambda *args, **kwargs: {}\n'
                'def gate(*args):\n'
                '    if os.environ.get("FIXTURE_DENY") == "true":\n'
                '        raise ValueError("fixture authority denied")\n'
                '    return {"schema": 1, "status": "allowed"}\n'
                'common.gate = gate\n'
                f'runpy.run_path({str(ROOT / "modules/ci/authority/_source/decisions/publication.py")!r}, run_name="__main__")\n'
            )
            environment = dict(os.environ, MAESTRO_SYSTEM_ROOT=str(ROOT),
                               MAESTRO_DECISIONS_SOURCE=str(source), DECISION_REQUIRE_HANDOFF='false')
            environment.pop('DECISION_ADMISSION', None)
            command = ['bash', str(ROOT / 'modules/ci/authority/_source/decision-publication.sh')]
            for output in ('security-report/publication.json', 'custom/nested/publication.json'):
                if output.startswith('custom/'):
                    environment['DECISION_ADMISSION'] = output
                result = subprocess.run(command, cwd=workspace, env=environment, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((workspace / output).read_text())['status'], 'allowed')
            environment.update(DECISION_ADMISSION='denied/nested/publication.json', FIXTURE_DENY='true')
            result = subprocess.run(command, cwd=workspace, env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('fixture authority denied', result.stderr)
            self.assertFalse((workspace / environment['DECISION_ADMISSION']).exists())

    def test_pending_discovery_reads_detail_count_and_rejects_changed_heads_or_extra_files(self):
        repository = 'closure-labs/maestro'
        cfg = {'repository': repository, 'botLogin': 'review[bot]'}
        proposal = {'schema': 1, 'kind': 'security-findings', 'payload': {}}
        path = retained.authority.proposal_path(proposal)
        # GitHub's PR-list response intentionally has no changed_files field.
        pull = {'number': 7, 'user': {'login': 'review[bot]', 'type': 'Bot'},
                'head': {'sha': 'a' * 40, 'ref': 'automation/decision-test',
                         'repo': {'full_name': repository}}}
        detail = dict(pull, state='open', base={'ref': 'main'}, changed_files=1)
        files = [{'filename': path, 'status': 'added'}]

        def collection(api, endpoint):
            return files if endpoint.endswith('/files') else [pull]

        with patch.object(retained.authority, 'collection', side_effect=collection), \
             patch.object(retained.authority, 'github_api', return_value=detail) as api, \
             patch.object(retained.authority, 'document_at', return_value=proposal) as document:
            self.assertEqual(retained.pending(cfg), {retained.canonical_hash(proposal): proposal})
            api.assert_called_once_with(f'repos/{repository}/pulls/7')
            self.assertEqual(document.call_args.args[-1], 'a' * 40)
            for count in (None, True, 2):
                with self.subTest(changed_files=count):
                    detail['changed_files'] = count
                    with self.assertRaisesRegex(ValueError, 'unexpected files'):
                        retained.pending(cfg)
            detail['changed_files'] = 1
            detail['head'] = dict(pull['head'], sha='b' * 40)
            with self.assertRaisesRegex(ValueError, 'changed during discovery'):
                retained.pending(cfg)

    def test_retained_input_hashes_bind_all_three_original_documents(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            inventory = directory / 'inventory'
            inventory.mkdir()
            values = {'maestro-system.cdx.json': b'system', 'xen-orchestra-supply.cdx.json': b'supply', 'Cargo.lock': b'lock'}
            lines = []
            for name, content in values.items():
                (inventory / name).write_bytes(content)
                lines.append(hashlib.sha256(content).hexdigest() + '  /original/candidate/' + name)
            checksum = directory / 'inputs.sha256'
            checksum.write_text('\n'.join(lines) + '\n')
            native = {'evidence': {'inputHashes': {'sha256': refresh.sha(checksum), 'size': checksum.stat().st_size},
                                   'inventory': {'sha256': refresh.sha(inventory / 'maestro-system.cdx.json'), 'size': len(b'system')}}}
            self.assertEqual(refresh.verify_inputs(directory, native), inventory)
            (inventory / 'Cargo.lock').write_bytes(b'changed-lock')
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                refresh.verify_inputs(directory, native)

    def test_edited_input_checksum_cannot_replace_authenticated_lock_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'inputs.sha256').write_text('forged')
            with self.assertRaisesRegex(ValueError, 'checksum file differs'):
                refresh.verify_inputs(directory, {'evidence': {'inputHashes': {'sha256': 'a' * 64, 'size': 6}}})

    def test_realization_checks_actual_nar_hash_even_for_existing_store_paths(self):
        value = {'products': {'maestro': {'storePath': '/nix/store/' + 'a' * 32 + '-root', 'narHash': 'expected'}}}
        with patch.object(refresh.Path, 'exists', return_value=True), patch.object(refresh, 'path_identities', return_value={}):
            with self.assertRaisesRegex(ValueError, 'NAR identity mismatch'):
                refresh.realize(value)

    def test_refresh_restores_authenticated_transport_before_verifying_actual_nars(self):
        path = '/nix/store/' + 'a' * 32 + '-root'
        identity = {'storePath': path, 'narHash': 'expected'}
        value = {'products': {'maestro': identity}, 'roots': {'root': dict(identity, profile='maestro')}}
        manifest = {'schema': 1, 'parts': {'distribution-cache.tar.part-000': {}}}
        with patch.object(refresh, 'distribution_cache') as cache, \
             patch.object(refresh.Path, 'exists', return_value=True), \
             patch.object(refresh, 'path_identities', return_value={path: identity}):
            refresh.realize(value, Path('/authenticated'), manifest)
        cache.return_value.restore.assert_called_once_with(Path('/authenticated'), manifest, [identity])

    def test_missing_legacy_root_cannot_trigger_unevaluated_rebuild_or_cache_substitution(self):
        value = {'products': {'maestro': {'storePath': '/nix/store/' + 'a' * 32 + '-root', 'narHash': 'expected'}}}
        with patch.object(refresh.Path, 'exists', return_value=False), \
             patch.object(refresh.subprocess, 'run', side_effect=AssertionError('No implicit build or download')):
            with self.assertRaisesRegex(ValueError, 'authenticated distribution transport'):
                refresh.realize(value)

    def test_refresh_keeps_product_bytes_and_uses_original_lock_with_fresh_native_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'source', root / 'fresh'
            (source / 'inventory').mkdir(parents=True)
            for name in ['Cargo.lock', 'maestro-system.cdx.json', 'xen-orchestra-supply.cdx.json']:
                (source / 'inventory' / name).write_text('retained data')
            product = {'schema': 1, 'repository': 'closure-labs/maestro', 'revision': 'a' * 40,
                       'products': {}, 'assets': {}}
            original_bytes = ('  ' + json.dumps(product, indent=3) + '\n').encode()
            (source / 'product.json').write_bytes(original_bytes)
            native_time = dt.datetime.now(dt.timezone.utc).isoformat()
            native = {'status': 'complete', 'scannerHealth': 'healthy', 'subjects': [], 'scannedAt': native_time}
            transport_bytes = b'authenticated binary cache transport'
            (source / 'distribution-cache.tar.part-000').write_bytes(transport_bytes)
            transport = {'schema': 1, 'parts': {'distribution-cache.tar.part-000': {
                'sha256': hashlib.sha256(transport_bytes).hexdigest(), 'size': len(transport_bytes)}},
                'archiveSha256': hashlib.sha256(transport_bytes).hexdigest(), 'archiveSize': len(transport_bytes)}
            old = {'revision': 'a' * 40, 'producer': {'workflow': '.github/workflows/release-continuation.yml',
                    'signerWorkflow': '.github/workflows/release.yml', 'revision': 'c' * 40, 'runId': 7, 'runAttempt': 1},
                   'profiles': {'maestro': {'subjects': []}}, 'transport': transport}
            env = {'DECISION_EVIDENCE_DIRECTORY': str(source), 'SECURITY_OUTPUT': str(output),
                   'MAESTRO_SYSTEM_ROOT': str(root), 'GITHUB_SHA': 'b' * 40,
                   'GITHUB_RUN_ID': '50', 'GITHUB_RUN_ATTEMPT': '2'}
            def scanner(argv, **kwargs):
                self.assertEqual(argv, ['maestro-ci-security-scan'])
                self.assertEqual(kwargs['env']['SECURITY_CARGO_LOCK'], str(output / 'inventory/Cargo.lock'))
                (output / 'security-result.json').write_text(json.dumps(native))
            with patch.dict(os.environ, env), patch.object(refresh.common, 'config', return_value={'repository': 'closure-labs/maestro'}), \
                 patch.object(refresh.common, 'scans', return_value=old) as authenticate, \
                 patch.object(refresh.common, 'product', return_value=product), \
                 patch.object(refresh, 'verify_inputs', return_value=source / 'inventory'), \
                 patch.object(refresh, 'realize'), patch.object(refresh.subprocess, 'run', side_effect=scanner), \
                 patch.object(refresh.common, 'emit'):
                refresh.main()
            self.assertTrue(authenticate.call_args.kwargs['allow_expired'])
            self.assertEqual((output / 'product.json').read_bytes(), original_bytes)
            result = json.loads((output / 'scans.json').read_text())
            self.assertEqual(result['revision'], 'a' * 40)
            self.assertEqual(result['producer']['revision'], 'b' * 40)
            self.assertEqual(result['producer']['runId'], 50)
            self.assertEqual(result['productProducer'], old['producer'])
            self.assertEqual(result['scannedAt'], native_time)
            self.assertEqual(result['transport'], transport)
            self.assertEqual((output / 'distribution-cache.tar.part-000').read_bytes(), transport_bytes)

    def test_old_workflow_success_and_pending_review_are_attention_not_authority(self):
        now = dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc)
        runs = [{'status': 'completed', 'conclusion': 'success', 'head_branch': 'main',
                 'path': '.github/workflows/security.yml', 'event': 'schedule',
                 'updated_at': (now - dt.timedelta(hours=37)).isoformat()}]
        pulls = [{'state': 'open', 'number': 7, 'user': {'login': 'review[bot]'},
                  'head': {'ref': 'automation/decision-abc'}, 'base': {'ref': 'main'},
                  'created_at': (now - dt.timedelta(hours=73)).isoformat()}]
        self.assertEqual(len(health.problems(runs, pulls, 'review[bot]', now)), 2)
        runs[0]['updated_at'] = now.isoformat()
        pulls[0]['created_at'] = now.isoformat()
        self.assertEqual(health.problems(runs, pulls, 'review[bot]', now), [])

    def test_fork_or_unrelated_workflow_success_does_not_clear_missing_audit(self):
        now = dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc)
        runs = [{'status': 'completed', 'conclusion': 'success', 'head_branch': 'feature',
                 'path': '.github/workflows/security.yml', 'event': 'pull_request', 'updated_at': now.isoformat()}]
        self.assertEqual(len(health.problems(runs, [], 'review[bot]', now)), 1)

    def test_policy_only_dispatch_is_not_a_native_security_audit(self):
        now = dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc)
        run = {'status': 'completed', 'conclusion': 'success', 'head_branch': 'main',
               'path': '.github/workflows/security.yml', 'event': 'workflow_dispatch', 'updated_at': now.isoformat()}
        self.assertEqual(len(health.problems([run], [], 'review[bot]', now)), 1)
        run['_nativeAudit'] = True
        self.assertEqual(health.problems([run], [], 'review[bot]', now), [])

    def test_health_issue_is_idempotent_and_closes_on_recovery(self):
        writes = []
        def write(endpoint, payload, method):
            writes.append((endpoint, payload, method))
        self.assertEqual(health.write_issue('closure-labs/maestro', [], ['Needs attention.'], write), 'attention-required')
        issue = {'number': 3, **writes[0][1]}
        writes.clear()
        health.write_issue('closure-labs/maestro', [issue], ['Needs attention.'], write)
        self.assertEqual(writes, [])
        self.assertEqual(health.write_issue('closure-labs/maestro', [issue], [], write), 'healthy')
        self.assertEqual(writes[0][1]['state'], 'closed')

    def test_health_refuses_duplicate_issue_writers(self):
        issues = [{'number': n, 'title': health.TITLE, 'body': health.MARKER} for n in [1, 2]]
        with self.assertRaisesRegex(ValueError, 'Multiple health'):
            health.write_issue('closure-labs/maestro', issues, ['Attention'], lambda *_: None)

    def test_handoff_uses_exact_official_lock_node(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = {'root': 'root', 'nodes': {'root': {'inputs': {'xen-orchestra-ce': 'xo'}},
                       'xo': {'locked': {'type': 'github', 'owner': 'closure-labs', 'repo': 'xo-nixpkg', 'rev': 'a' * 40}}}}
            (root / 'flake.lock').write_text(json.dumps(value))
            self.assertEqual(handoff.locked_revision(root), 'a' * 40)
            value['nodes']['xo']['locked']['owner'] = 'attacker'
            (root / 'flake.lock').write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'official locked revision'):
                handoff.locked_revision(root)

    def test_handoff_uses_typed_channel_and_defaults_historical_context_to_latest(self):
        for runtime, expected in [({}, 'xo-latest'), ({'xoChannel': 'stable'}, 'xo-stable'),
                                  ({'xoChannel': 'rolling'}, 'xo-rolling')]:
            with self.subTest(runtime=runtime), patch.object(handoff, 'runtime_context', return_value=({'runtime': runtime}, [])):
                self.assertEqual(handoff.expected_channel(Path('/retained')), expected)
        with patch.object(handoff, 'runtime_context', return_value=({'runtime': {'xoChannel': 'untrusted'}}, [])):
            with self.assertRaisesRegex(ValueError, 'typed runtime XO channel'):
                handoff.expected_channel(Path('/retained'))

    def test_historical_handoff_uses_candidate_binding_and_lock_with_current_live_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'modules/ci/authority/_source').mkdir(parents=True)
            live = {'schema': 1, 'mode': 'official', 'revision': 'f' * 40}
            (root / 'modules/ci/authority/_source/xo-handoff.json').write_text(json.dumps(live))
            identity = {'storePath': '/nix/store/' + 'a' * 32 + '-xo', 'narHash': 'sha256-' + 'A' * 43 + '='}
            candidate = {'schema': 1, 'mode': 'official', 'repository': 'closure-labs/xo-nixpkg',
                         'revision': 'e' * 40, 'channel': 'xo-latest', **identity,
                         'packet': {'reference': 'ghcr.io/closure-labs/xo-nixpkg-products@sha256:' + 'a' * 64, 'sha256': 'b' * 64}}
            lock = {'nodes': {'root': {'inputs': {'xen-orchestra-ce': 'xo'}},
                    'xo': {'locked': {'type': 'github', 'owner': 'closure-labs', 'repo': 'xo-nixpkg', 'rev': 'e' * 40}}}}
            upstream = {'repository': 'closure-labs/xo-nixpkg', 'enabled': True}
            queried = []
            def document(api, repository, path, revision):
                queried.append((repository, path, revision))
                if repository == 'closure-labs/xo-nixpkg':
                    self.assertEqual(os.environ['GH_TOKEN'], 'xo-read-token')
                else:
                    self.assertEqual(os.environ['GH_TOKEN'], 'maestro-read-token')
                if path == 'flake.lock':
                    return lock
                if repository == 'closure-labs/xo-nixpkg':
                    return upstream
                return candidate if revision == 'a' * 40 else live
            env = {'MAESTRO_SYSTEM_ROOT': str(root), 'DECISION_EVIDENCE_DIRECTORY': str(root / 'retained'),
                   'GH_TOKEN': 'maestro-read-token', 'XO_AUTHORITY_TOKEN': 'xo-read-token'}
            with patch.dict(os.environ, env), \
                 patch.object(handoff.common, 'config', side_effect=[{'repository': 'closure-labs/maestro'}, upstream]) as config, \
                 patch.object(handoff.common, 'scans', return_value={}), \
                 patch.object(handoff.common, 'product', return_value={'revision': 'a' * 40}), \
                 patch.object(handoff.common, 'main_revision', return_value='c' * 40), \
                 patch.object(handoff, 'document_at', side_effect=document), \
                 patch.object(handoff, 'actual_output', return_value=identity), \
                 patch.object(handoff, 'expected_channel', return_value='xo-latest'), \
                 patch.object(handoff.packets, 'metadata_bytes', return_value=b'{}') as metadata, \
                 patch.object(handoff.common, 'command', return_value='{"status":"covered"}') as verify, \
                 patch.object(handoff.common, 'emit'):
                handoff.main()
            self.assertEqual([call.args[2] for call in metadata.call_args_list], ['scans.json','product.json','handoff-xo-latest.json'])
            self.assertIn(('closure-labs/maestro', 'flake.lock', 'a' * 40), queried)
            self.assertIn(('closure-labs/maestro', 'modules/ci/authority/_source/xo-handoff.json', 'a' * 40), queried)
            self.assertTrue(config.call_args.kwargs['live'])
            self.assertTrue(config.call_args.kwargs['enabled'])
            args = verify.call_args.args[0]
            self.assertEqual(args[args.index('--expected-revision') + 1], 'e' * 40)

    def test_retained_pending_packet_schedules_work_without_human_authorization(self):
        proposal = {'schema': 1, 'kind': 'security-findings', 'payload': {'disposition': 'accepted'}}
        cfg = {'profiles': ['maestro']}
        with patch.object(retained.common, 'authorize', side_effect=AssertionError('No authority may be granted')):
            digest, selected = retained.select(cfg, {}, {'a' * 64: proposal})
        self.assertEqual(digest, 'a' * 64)
        self.assertIs(selected, proposal)

    def test_retained_multiple_candidates_require_explicit_selection(self):
        proposal = {'schema': 1, 'kind': 'security-findings', 'payload': {'disposition': 'accepted'}}
        cfg = {'profiles': ['maestro']}
        proposals = {'a' * 64: proposal, 'b' * 64: proposal}
        with self.assertRaisesRegex(ValueError, 'unambiguous'):
            retained.select(cfg, {}, proposals)
        self.assertEqual(retained.select(cfg, {}, proposals, proposal_hash='b' * 64)[0], 'b' * 64)

    def test_retained_recovery_skips_published_exact_release_tag(self):
        proposal = {'schema': 1, 'kind': 'release-product', 'payload': {
            'disposition': 'accepted', 'product': {'assets': {'maestro-v1.2.3.iso.sha256': 'a' * 64}}}}
        with self.assertRaises(retained.NoCandidate):
            retained.select({'profiles': ['maestro']}, {}, {'a' * 64: proposal},
                            release_only=True, published_tags={'v1.2.3'})
        selected = retained.select({'profiles': ['maestro']}, {}, {'a' * 64: proposal}, release_only=True)
        self.assertEqual(selected[0], 'a' * 64)

    def test_official_discovery_selects_newest_version_and_preserves_explicit_history(self):
        def proposal(version):
            return {'kind': 'release-product', 'payload': {'disposition': 'accepted',
                    'product': {'assets': {f'maestro-v{version}.iso.sha256': 'a' * 64}}}}
        older, newer = proposal('3.9.0'), proposal('3.10.0')
        proposals = {'a' * 64: older, 'b' * 64: newer}
        with patch.object(retained.common, 'authorize', side_effect=AssertionError('Selection grants no authority')):
            self.assertEqual(retained.select({}, {}, proposals, release_only=True)[0], 'b' * 64)
            self.assertEqual(retained.select({}, {}, proposals, release_only=True,
                                            proposal_hash='a' * 64)[0], 'a' * 64)
        for filters in ({'published_tags': {'v3.10.0'}},
                        {'suppressed_products': {retained.canonical_hash(newer['payload']['product'])}}):
            with self.subTest(filters=filters), self.assertRaises(retained.NoCandidate):
                retained.select({}, {}, proposals, release_only=True, **filters)
        with patch.object(retained.common, 'active_release', return_value=('b' * 64, newer)):
            self.assertEqual(retained.select({}, {'b' * 64: newer}, {'a' * 64: older},
                                            release_only=True)[0], 'b' * 64)
        proposals['c' * 64] = proposal('3.10.0')
        with self.assertRaisesRegex(ValueError, 'unambiguous'):
            retained.select({}, {}, proposals, release_only=True)

    def test_retained_optional_only_suppresses_absence_not_integrity_or_api_errors(self):
        arguments = ['retained', '--config', 'policy.json', '--optional']
        cfg = {'repository': 'closure-labs/maestro'}
        with patch.object(sys, 'argv', arguments), patch.object(retained.common, 'config', return_value=cfg), \
             patch.object(retained.common, 'ledger', return_value=('a' * 40, {})), \
             patch.object(retained, 'pending', return_value={}), \
             patch.object(retained, 'select', side_effect=retained.NoCandidate('No candidate')), \
             patch.object(retained, 'workflow_metadata') as metadata, patch.object(retained.common, 'emit'):
            retained.main()
            self.assertEqual(metadata.call_args.args[0]['available'], 'false')
        with patch.object(sys, 'argv', arguments), patch.object(retained.common, 'config', return_value=cfg), \
             patch.object(retained.common, 'ledger', side_effect=ValueError('API failed')):
            with self.assertRaisesRegex(ValueError, 'API failed'):
                retained.main()


class FreshUpstreamHandoff(unittest.TestCase):
    def setUp(self):
        registry = patch.object(handoff.packets, 'REFERENCE', handoff.re.compile(
            r'ghcr\.io/closure-labs/xo-nixpkg-products@sha256:[0-9a-f]{64}'))
        registry.start()
        self.addCleanup(registry.stop)
        self.source = {'schema': 1, 'mode': 'official', 'repository': 'closure-labs/xo-nixpkg',
                       'revision': 'a'*40, 'channel': 'xo-latest',
                       'storePath': '/nix/store/'+'b'*32+'-xo', 'narHash': 'sha256-'+'A'*43+'=',
                       'packet': {'reference': 'ghcr.io/closure-labs/xo-nixpkg-products@sha256:'+'c'*64,
                                  'sha256': 'd'*64}}
        self.current = json.loads(json.dumps(self.source))
        self.current['packet'] = {'reference': 'ghcr.io/closure-labs/xo-nixpkg-products@sha256:'+'e'*64,
                                  'sha256': 'f'*64}
        self.product = {'schema': 1, 'revision': 'a'*40, 'products': {'xo-latest': {'narHash': 'latest'},
                        'xo-stable': {'narHash': 'stable'}}, 'roots': {'tool': {'narHash': 'tool'}},
                        'assets': {'inventory.json': 'inventory'}}

    def read(self, reference, digest, name):
        if name == 'product.json':
            return json.dumps(self.product).encode()
        return b'{}'

    def test_same_packet_materializes_only_the_existing_three_documents(self):
        with patch.object(handoff.packets, 'metadata_bytes', side_effect=self.read) as read:
            documents = handoff.handoff_documents(self.source, self.source, 'xo-latest')
        self.assertEqual(set(documents), {'scans.json', 'product.json', 'handoff-xo-latest.json'})
        self.assertEqual(read.call_count, 3)

    def test_fresh_packet_requires_authenticated_full_original_product(self):
        with patch.object(handoff.packets, 'metadata_bytes', side_effect=self.read) as read:
            handoff.handoff_documents(self.source, self.current, 'xo-latest')
        self.assertEqual(read.call_args_list[0].args,
                         (self.source['packet']['reference'], self.source['packet']['sha256'], 'product.json'))
        self.assertEqual([call.args[2] for call in read.call_args_list[1:]],
                         ['product.json', 'scans.json', 'handoff-xo-latest.json'])
        self.assertTrue(all(call.args[0] == self.current['packet']['reference']
                            for call in read.call_args_list[1:]))

    def test_matching_runtime_root_cannot_replace_other_products_roots_or_assets(self):
        for section, key in [('products', 'xo-stable'), ('roots', 'tool'), ('assets', 'inventory.json')]:
            changed = json.loads(json.dumps(self.product))
            changed[section][key] = 'different'
            def read(reference, digest, name):
                if reference == self.current['packet']['reference'] and name == 'product.json':
                    return json.dumps(changed).encode()
                return self.read(reference, digest, name)
            with self.subTest(section=section), patch.object(handoff.packets, 'metadata_bytes', side_effect=read):
                with self.assertRaisesRegex(ValueError, 'immutable upstream product'):
                    handoff.handoff_documents(self.source, self.current, 'xo-latest')

    def test_changed_current_binding_cannot_select_its_packet(self):
        for key in ('repository', 'revision', 'channel', 'storePath', 'narHash', 'mode'):
            current = json.loads(json.dumps(self.current))
            current[key] = 'custom' if key == 'mode' else 'different'
            with self.subTest(key=key), patch.object(handoff.packets, 'metadata_bytes', side_effect=self.read) as read:
                handoff.handoff_documents(self.source, current, 'xo-latest')
            self.assertEqual(read.call_count, 3)
            self.assertTrue(all(call.args[0] == self.source['packet']['reference'] for call in read.call_args_list))

    def test_selected_fresh_packet_failure_never_falls_back(self):
        def read(reference, digest, name):
            if reference == self.current['packet']['reference']:
                raise ValueError('Packet member integrity failure')
            return self.read(reference, digest, name)
        with patch.object(handoff.packets, 'metadata_bytes', side_effect=read) as fetch:
            with self.assertRaisesRegex(ValueError, 'integrity'):
                handoff.handoff_documents(self.source, self.current, 'xo-latest')
        self.assertEqual(fetch.call_count, 2)

    def test_invalid_current_packet_and_original_integrity_fail_before_fresh_reads(self):
        for packet in (None, {}, {'reference': 'https://example.invalid', 'sha256': 'f'*64}):
            current = dict(self.current, packet=packet)
            with self.subTest(packet=packet), patch.object(handoff.packets, 'metadata_bytes') as read:
                with self.assertRaisesRegex(ValueError, 'packet reference'):
                    handoff.handoff_documents(self.source, current, 'xo-latest')
                read.assert_not_called()
        with patch.object(handoff.packets, 'metadata_bytes', side_effect=ValueError('integrity')) as read:
            with self.assertRaisesRegex(ValueError, 'integrity'):
                handoff.handoff_documents(self.source, self.current, 'xo-latest')
            self.assertEqual(read.call_count, 1)

    def test_schema_aliases_cannot_match_original_product_or_policy(self):
        for alias in (True, 1.0):
            changed = dict(self.product, schema=alias)
            def read(reference, digest, name):
                if reference == self.current['packet']['reference'] and name == 'product.json':
                    return json.dumps(changed).encode()
                return self.read(reference, digest, name)
            with self.subTest(alias=alias), patch.object(handoff.packets, 'metadata_bytes', side_effect=read) as fetch:
                with self.assertRaisesRegex(ValueError, 'immutable upstream product'):
                    handoff.handoff_documents(self.source, self.current, 'xo-latest')
                self.assertEqual(fetch.call_count, 2)
            with patch.object(handoff.packets, 'metadata_bytes') as fetch:
                with self.assertRaisesRegex(ValueError, 'policy schema'):
                    handoff.handoff_documents(self.source, dict(self.current, schema=alias), 'xo-latest')
                fetch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
