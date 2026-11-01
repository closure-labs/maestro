# SPDX-License-Identifier: Apache-2.0
"""Synthetic twelve-record workload; exercise reuse, live failures and receipt recovery."""
import base64
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[5] / 'modules/ci/authority/_source/decisions'))
import common
import decision_authority as authority
import decision_packets as packets
import recovery_context as context
import security_recovery as recovery
from test_core import CFG, scan
from test_reconciliation import release

REVISION, HEAD, MERGE = 'a' * 40, 'b' * 40, 'c' * 40


def historical(value, number=7):
    return {'schema': 1, 'status': 'historical-provenance', 'repository': CFG['repository'],
            'proposalHash': common.canonical_hash(value), 'path': authority.proposal_path(value),
            'pullRequest': number, 'reviewId': None, 'reviewer': None, 'reviewedHead': HEAD,
            'mergeCommit': MERGE, 'permissionPolicy': 'immutable-bot-merge-provenance'}


class Workload:
    def __init__(self):
        self.records, parent = {}, []
        native = scan()
        self.producer = dict(native['producer'], repository=CFG['repository'], revision=native['revision'], sourceRevision=native['revision'])
        for n in range(12):
            if n == 10:
                parent = [self.ancestor]
            value = {'schema': 1, 'kind': 'security-findings', 'payload': {
                'disposition': 'accepted', 'rationale': 'Synthetic history ' + str(n), 'supersedes': parent,
                'profiles': {p: recovery.normalize_findings(s, p) for p, s in native['profiles'].items()},
                'securityContexts': {}, 'packet': {'reference': packets.REGISTRY + '@sha256:' + 'd' * 64,
                                                 'sha256': 'e' * 64, 'producer': self.producer}}}
            digest = common.canonical_hash(value)
            self.records[digest] = value
            if n == 9:
                self.ancestor = digest
            if n < 10:
                parent = [digest]
        for n in range(3):
            value = release({'schema': 1, 'assets': {'fixture-' + str(n): 'e' * 64}})
            self.records[common.canonical_hash(value)] = value
        security = {h: p for h, p in self.records.items() if p['kind'] == 'security-findings'}
        self.parents = sorted(set(security) - {h for p in security.values() for h in p['payload']['supersedes']})
        self.request = {'schema': 1, 'mainRevision': REVISION, 'graphHash': common.canonical_hash(self.records),
                        'policyHash': common.canonical_hash(CFG), 'parents': self.parents,
                        'rationale': 'Fixture only; grants no acceptance.', 'disposition': 'accepted'}
        self.revoked, self.rules_changed, self.main = False, False, REVISION
        self.blobs, self.paths, self.tree = {}, {}, []
        for value in [CFG, *self.records.values()]:
            raw = json.dumps(value, sort_keys=True, indent=2).encode()
            sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            self.blobs[sha] = {'sha': sha, 'size': len(raw), 'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
            path = CFG['policyPath'] if value is CFG else authority.proposal_path(value)
            self.paths[path] = sha
            if value is not CFG:
                self.tree.append({'path': path, 'type': 'blob', 'mode': '100644', 'sha': sha, 'size': len(raw)})
        assert sum(len(json.dumps(p)) for p in self.records.values()) < 128 * 1024

    def api(self, endpoint):
        if '/git/ref/heads/main' in endpoint:
            return {'object': {'sha': self.main}}
        if '/git/trees/' in endpoint:
            return {'truncated': False, 'tree': deepcopy(self.tree)}
        if '/git/blobs/' in endpoint:
            return deepcopy(self.blobs[endpoint.rsplit('/', 1)[-1]])
        if '/contents/' in endpoint:
            path = endpoint.split('/contents/', 1)[1].split('?ref=')[0]
            return dict(self.blobs[self.paths[path]], type='file')
        if '/rules/branches/main' in endpoint:
            if self.rules_changed:
                return []
            return [{'type': 'required_status_checks', 'parameters': {'required_status_checks': [
                {'context': 'Maintainer decision authority', 'integration_id': CFG['appId']}]}}]
        raise AssertionError('Unexpected fixture API: ' + endpoint)

    def immutable(self, value, number, repository, bot, **kwargs):
        assert kwargs.get('require_merged') is True and kwargs.get('require_live_review') is False
        for revision in (HEAD, MERGE, REVISION):
            observed = authority.document_at(self.api, repository, authority.proposal_path(value), revision,
                                             context=kwargs.get('context'))
            assert observed == value
        return historical(value, number)

    def live(self, cfg, value, *args, **kwargs):
        assert kwargs.get('context') is None
        if self.revoked:
            raise authority.HumanDecisionRequired('review or membership revoked')
        for revision in (HEAD, MERGE, REVISION):
            assert authority.document_at(self.api, cfg['repository'], authority.proposal_path(value), revision) == value
        return {'status': 'authorized'}

    def patches(self, stack):
        result = {}
        result['api'] = stack.enter_context(patch.object(authority, 'github_api', side_effect=self.api))
        result['origin'] = stack.enter_context(patch.object(authority, 'find_origin_pr', return_value=7))
        result['history'] = stack.enter_context(patch.object(authority, 'verify_proposal', side_effect=self.immutable))
        result['live'] = stack.enter_context(patch.object(common, 'authorize', side_effect=self.live))
        result['packets'] = stack.enter_context(patch.object(recovery, 'evidence'))
        result['graphs'] = stack.enter_context(patch.object(common, 'security_graph', wraps=common.security_graph))
        result['blobs'] = stack.enter_context(patch.object(authority, 'document_blob', wraps=authority.document_blob))
        return result

    def legacy_pass(self, verify_packets):
        revision, records = common.ledger(CFG)
        assert revision == self.request['mainRevision'] and common.canonical_hash(records) == self.request['graphHash']
        assert authority.document_at(self.api, CFG['repository'], CFG['policyPath'], revision) == CFG
        common.required_check(CFG)
        leaves = recovery.security_leaves(CFG, records)
        assert sorted(leaves) == self.parents
        for value in leaves.values():
            common.authorize(CFG, value)
        if verify_packets:
            for value in records.values():
                if value['kind'] == 'security-findings':
                    common.historical_provenance(CFG, value)
                    recovery.evidence(CFG, value)
        assert common.main_revision(CFG) == revision


class RecoveryContext(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_STEP_SUMMARY=str(self.root / 'summary.md')))
        self.stack.enter_context(redirect_stdout(io.StringIO()))
        self.work = Workload()
        self.mocks = self.work.patches(self.stack)

    def test_before_after_full_five_pass_work_counts_preserve_live_work(self):
        passes = [True, False, True, False, False]
        authority.document_at(self.work.api, CFG['repository'], CFG['policyPath'], REVISION)
        for full in passes:
            self.work.legacy_pass(full)
        before = {k: self.mocks[k].call_count for k in ('history', 'live', 'packets', 'blobs', 'graphs')}
        self.assertEqual(before, {'history': 124, 'live': 10, 'packets': 24, 'blobs': 483, 'graphs': 10})
        for mock in self.mocks.values():
            mock.reset_mock()
        authority.document_at(self.work.api, CFG['repository'], CFG['policyPath'], REVISION)
        with context.lifetime('reconcile') as state:
            for full in passes:
                recovery.validate(CFG, self.work.request, verify_packets=full)
            counts = dict(state.counts)
        after = {k: self.mocks[k].call_count for k in ('history', 'live', 'packets', 'blobs', 'graphs')}
        self.assertEqual(after, {'history': 12, 'live': 10, 'packets': 24, 'blobs': 147, 'graphs': 10})
        self.assertEqual({k: counts[k] for k in ('ledgerReads', 'policyReads', 'ruleChecks', 'mainReads')},
                         dict.fromkeys(('ledgerReads', 'policyReads', 'ruleChecks', 'mainReads'), 5))
        self.assertEqual(counts['historicalChecks'], 12)
        self.assertEqual(counts['historicalHits'], 112)
        self.assertEqual(counts['liveParents'], 10)
        self.assertEqual(counts['packetProofs'], 24)
        self.assertTrue(state.closed)
        self.assertEqual(len(state.history), 0)
        self.assertEqual(len(state.documents), 0)
        self.assertEqual(len(state.blobs), 0)
        receipt = json.loads(state.receipt.read_text())
        self.assertFalse(receipt['authorization'])
        self.assertEqual(receipt['counts'], counts)
        # Deterministic fixture counts, not a prediction of hosted wall time or wire traffic.
        with redirect_stdout(sys.__stdout__):
            print(json.dumps({'fixtureBefore': before, 'fixtureAfter': after, 'hostedMeasurement': False}))

    def test_new_invocation_cannot_reuse_a_previous_proof_result(self):
        recovery.validate(CFG, self.work.request)
        recovery.validate(CFG, self.work.request)
        self.assertEqual(self.mocks['history'].call_count, 24)
        receipts = [json.loads(p.read_text()) for p in self.root.glob('security-recovery-*/receipt.json')]
        self.assertEqual(len({p['invocation'] for p in receipts}), 2)
        self.assertTrue(all(p['status'] == 'completed' for p in receipts))
        self.assertIsNone(context.current())

    def test_cached_history_does_not_cache_revocation_or_membership(self):
        with self.assertRaisesRegex(ValueError, 'revoked'):
            with context.lifetime('reconcile') as state:
                recovery.validate(CFG, self.work.request)
                self.work.revoked = True
                recovery.validate(CFG, self.work.request, verify_packets=False)
        self.assertTrue(state.closed)
        self.assertEqual(len(state.history), 0)
        self.assertGreater(self.mocks['live'].call_count, 2)
        self.assertEqual(json.loads(state.receipt.read_text())['phase'], 'live-parents')

    def test_cached_history_never_skips_changed_packet_proofs(self):
        with self.assertRaisesRegex(ValueError, 'mutated packet'):
            with context.lifetime('reconcile'):
                recovery.validate(CFG, self.work.request)
                self.mocks['packets'].side_effect = ValueError('mutated packet proof')
                recovery.validate(CFG, self.work.request)
        self.assertEqual(self.mocks['history'].call_count, 12)
        self.assertEqual(self.mocks['packets'].call_count, 13)

    def test_live_rules_and_main_are_not_cached(self):
        for change in ('rules', 'main'):
            self.work.rules_changed, self.work.main = False, REVISION
            with self.subTest(change=change), self.assertRaises(ValueError):
                with context.lifetime('reconcile'):
                    recovery.validate(CFG, self.work.request)
                    if change == 'rules':
                        self.work.rules_changed = True
                    else:
                        self.work.main = 'f' * 40
                    recovery.validate(CFG, self.work.request, verify_packets=False)

    def test_live_policy_read_cannot_use_a_cached_policy_conclusion(self):
        with context.lifetime('reconcile'):
            recovery.validate(CFG, self.work.request)
            changed = dict(CFG, enabled=True)
            raw = json.dumps(changed).encode()
            sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            self.work.blobs[sha] = {'sha': sha, 'size': len(raw), 'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
            self.work.paths[CFG['policyPath']] = sha
            with self.assertRaisesRegex(ValueError, 'current policy changed'):
                recovery.validate(CFG, self.work.request, verify_packets=False)

    def test_final_graph_read_rejects_a_race_after_cached_history(self):
        with context.lifetime('reconcile'):
            recovery.validate(CFG, self.work.request)
            reads = 0
            original = self.work.live
            def advance(*args, **kwargs):
                nonlocal reads
                result = original(*args, **kwargs)
                reads += 1
                if reads == 2:
                    self.work.main = 'f' * 40
                return result
            self.mocks['live'].side_effect = advance
            with self.assertRaisesRegex(ValueError, 'snapshot changed'):
                recovery.validate(CFG, self.work.request, verify_packets=False)

    def test_rebinding_changed_policy_request_or_trust_rejects_cached_proofs(self):
        for change in ('policy', 'request', 'trust'):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'binding changed'):
                with context.lifetime('reconcile') as state:
                    recovery.validate(CFG, self.work.request)
                    cfg, request = deepcopy(CFG), deepcopy(self.work.request)
                    if change == 'policy':
                        cfg['enabled'] = True
                        request['policyHash'] = common.canonical_hash(cfg)
                    elif change == 'request':
                        request['rationale'] = 'Changed request is a different proof epoch'
                    with patch.object(context, 'trust_version', return_value='f' * 64) if change == 'trust' else ExitStack():
                        state.bind(cfg, request, REVISION, self.work.records)
            self.assertTrue(state.closed)

    def test_graph_and_parent_mutations_reject_even_if_request_is_rehashed(self):
        with self.assertRaisesRegex(ValueError, 'binding changed'):
            with context.lifetime('reconcile'):
                recovery.validate(CFG, self.work.request)
                records = deepcopy(self.work.records)
                value = deepcopy(records[self.work.parents[0]])
                value['payload']['rationale'] = 'Concurrent new leaf'
                records[common.canonical_hash(value)] = value
                request = dict(self.work.request, graphHash=common.canonical_hash(records))
                with patch.object(common, 'ledger', return_value=(REVISION, records)):
                    recovery.validate(CFG, request)

    def test_historical_results_are_defensive_and_reject_mutated_cache_or_authority(self):
        with context.lifetime('reconcile') as state:
            recovery.validate(CFG, self.work.request)
            digest = self.work.parents[0]
            copy = state.history[digest]
            copy['reviewedHead'] = 'f' * 40
            self.assertEqual(state.history[digest]['reviewedHead'], HEAD)
            with self.assertRaisesRegex(ValueError, 'Only immutable'):
                state.history[digest] = dict(historical(self.work.records[digest]), status='authorized', reviewer='human')
            state.history._values[digest][0]['mergeCommit'] = 'f' * 40
            with self.assertRaisesRegex(ValueError, 'mutated'):
                common.historical_provenance(CFG, self.work.records[digest], context=state)

    def test_trust_change_poisoning_is_detected_on_a_cache_hit(self):
        with context.lifetime('reconcile') as state:
            recovery.validate(CFG, self.work.request)
            with patch.object(authority, 'APPROVER_TEAM_ID', authority.APPROVER_TEAM_ID + 1):
                with self.assertRaisesRegex(ValueError, 'trust binding changed'):
                    common.historical_provenance(CFG, self.work.records[self.work.parents[0]], context=state)
            self.assertTrue(state.closed)
            self.assertEqual(len(state.history), 0)

    def test_changed_git_proof_bytes_are_rejected_by_fresh_ledger_read(self):
        with context.lifetime('reconcile'):
            recovery.validate(CFG, self.work.request)
            blob = self.work.paths[authority.proposal_path(self.work.records[self.work.parents[0]])]
            self.work.blobs[blob]['content'] = base64.b64encode(b'forged').decode()
            with self.assertRaises(ValueError):
                recovery.validate(CFG, self.work.request, verify_packets=False)

    def test_membership_storage_and_cross_thread_reuse_are_forbidden(self):
        with context.lifetime('reconcile') as state:
            recovery.validate(CFG, self.work.request)
            with self.assertRaisesRegex(ValueError, 'cannot retain membership'):
                state.members = ['mutable member']
            with patch.object(context.threading, 'get_ident', return_value=-1):
                with self.assertRaisesRegex(ValueError, 'owner changed'):
                    common.historical_provenance(CFG, self.work.records[self.work.parents[0]], context=state)

    def test_expired_evidence_still_fails_after_immutable_cache_warmup(self):
        value = scan()
        with context.lifetime('reconcile'):
            recovery.validate(CFG, self.work.request)
            value['expiresAt'] = value['scannedAt']
            with patch.object(common, 'verify_producer') as producer:
                with self.assertRaisesRegex(ValueError, 'observation-expired'):
                    recovery.fresh(CFG, value)
                producer.assert_not_called()

    def test_cache_bounds_and_no_retained_large_documents(self):
        state = context.Invocation('reconcile')
        state.bind(CFG, self.work.request, REVISION, self.work.records)
        state.documents['large'] = {'value': 'x' * 1024**2}
        state.blobs['large'] = {'value': 'x' * 1024**2}
        state.documents.update({'large': {'value': 'x' * 1024**2}})
        state.blobs.setdefault('large', {'value': 'x' * 1024**2})
        self.assertEqual((len(state.documents), len(state.blobs)), (0, 0))
        with patch.object(context, 'MAX_PROOFS', 1):
            digest = self.work.parents[0]
            state.history[digest] = historical(self.work.records[digest])
            second = self.work.parents[1]
            with self.assertRaisesRegex(ValueError, 'budget'):
                state.history[second] = historical(self.work.records[second])
        state.close('completed')
        with self.assertRaisesRegex(ValueError, 'closed'):
            state.bind(CFG, self.work.request, REVISION, self.work.records)

    def test_pass_budget_fails_before_additional_network_work(self):
        with patch.object(context, 'MAX_PASSES', 1), self.assertRaisesRegex(ValueError, 'validation budget'):
            with context.lifetime('reconcile') as state:
                recovery.validate(CFG, self.work.request)
                before = self.mocks['api'].call_count
                try:
                    recovery.validate(CFG, self.work.request, verify_packets=False)
                finally:
                    self.assertEqual(self.mocks['api'].call_count, before)
        self.assertTrue(state.closed)

    def packet_push(self, state, *, interrupted=False):
        directory = self.root / ('packet-interrupted' if interrupted else 'packet-complete')
        directory.mkdir()
        (directory / 'scans.json').write_text('synthetic immutable file')
        def push(args, **kwargs):
            before = json.loads(state.receipt.read_text())
            self.assertEqual(before['phase'], 'packet-push-requested')
            self.assertTrue(before['packet']['tag'].startswith(packets.REGISTRY + ':packet-'))
            if interrupted:
                raise packets.RegistryUnavailable('simulated transport interruption')
            Path(args[args.index('--export-manifest') + 1]).write_bytes(b'{"synthetic":true}')
        with patch.object(packets, 'private_review_registry'), patch.object(packets, 'command', side_effect=push) as command:
            result = packets.push(directory, dict(self.work.producer, credential='do-not-log-me'), receipt=state.phase)
            self.assertEqual(command.call_count, 1)
            self.assertIn('org.opencontainers.image.created=1970-01-01T00:00:00Z', command.call_args.args[0])
            return result

    def test_exact_packet_receipt_survives_later_cancellation_and_is_not_authority(self):
        with self.assertRaises(KeyboardInterrupt):
            with context.lifetime('reconcile') as state:
                state.bind(CFG, self.work.request, REVISION, self.work.records)
                result = self.packet_push(state)
                raise KeyboardInterrupt()
        receipt = json.loads(state.receipt.read_text())
        self.assertEqual(receipt['phase'], 'packet-pushed')
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(receipt['packet']['reference'], result['reference'])
        self.assertEqual(receipt['packet']['sha256'], result['sha256'])
        self.assertFalse(receipt['authorization'])
        self.assertLess(state.receipt.stat().st_size, context.MAX_RECEIPT_BYTES)
        self.assertNotIn('do-not-log-me', state.receipt.read_text())
        self.assertNotIn(self.work.request['rationale'], state.receipt.read_text())
        self.assertIn('packet-pushed', (self.root / 'summary.md').read_text())
        self.assertNotIn('do-not-log-me', (self.root / 'summary.md').read_text())
        with self.assertRaises(ValueError):
            recovery.load_request(state.receipt.read_text())

    def test_uncertain_registry_write_retains_exact_target_without_retry(self):
        with self.assertRaisesRegex(ValueError, 'transport interruption'):
            with context.lifetime('reconcile') as state:
                state.bind(CFG, self.work.request, REVISION, self.work.records)
                self.packet_push(state, interrupted=True)
        receipt = json.loads(state.receipt.read_text())
        self.assertEqual(receipt['phase'], 'packet-push-requested')
        self.assertNotIn('reference', receipt['packet'])
        self.assertEqual(receipt['status'], 'failed')
        self.assertIn('sha256', receipt['packet'])
        self.assertTrue(state.closed)
        self.assertIsNone(context.current())

    def test_both_workflows_retain_receipts_after_cancellation(self):
        root = Path(__file__).resolve().parents[5]
        for filename, job in [('decisions.yml', 'reconcile'), ('decision-authority.yml', 'authority')]:
            value = json.loads(subprocess.check_output(['yq', '-o=json', '.', str(root / '.github/workflows' / filename)], text=True))
            steps = [s for s in value['jobs'][job]['steps']
                     if s.get('with', {}).get('name') == 'maestro-security-recovery-receipts']
            self.assertEqual(len(steps), 1)
            self.assertEqual(steps[0]['if'], 'always()')
            self.assertEqual(steps[0]['with']['path'], '${{ runner.temp }}/security-recovery-*/receipt.json')

    def test_receipt_symlink_failure_discards_proofs(self):
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            with context.lifetime('reconcile') as state:
                recovery.validate(CFG, self.work.request)
                target = self.root / 'untouched'
                target.write_text('unchanged')
                state.receipt.unlink()
                state.receipt.symlink_to(target)
                state.phase('evidence-verified')
        self.assertTrue(state.closed)
        self.assertEqual(len(state.history), 0)
        self.assertEqual(target.read_text(), 'unchanged')


if __name__ == '__main__':
    unittest.main()
