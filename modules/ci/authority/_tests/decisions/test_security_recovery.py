# SPDX-License-Identifier: Apache-2.0
"""Bounded recovery fixtures: no registry, credentials, production data or builds."""
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[5] / 'modules/ci/authority/_source/decisions'))
import common
import reconciliation
import security_recovery as recovery
from test_core import CFG, scan
from test_coverage_context import context
from test_check import GitHub as CheckGitHub, mod as checked, REPO, BOT, HEAD, MERGE


class SecurityRecovery(unittest.TestCase):
    def setUp(self):
        self.native = scan()
        self.native['profiles']['maestro']['securityContext'] = context()
        self.producer = dict(self.native['producer'], repository=CFG['repository'],
                             revision=self.native['revision'], sourceRevision=self.native['revision'])
        self.parent = self.record('original')
        self.parent_hash = common.canonical_hash(self.parent)
        self.one = self.record('first concurrent branch', [self.parent_hash])
        self.two = self.record('second concurrent branch', [self.parent_hash])
        self.two['payload']['packet']['producer']['runId'] += 1
        self.records = {common.canonical_hash(p): p for p in [self.parent, self.one, self.two]}
        self.parents = sorted(common.canonical_hash(p) for p in [self.one, self.two])
        self.request = {'schema': 1, 'mainRevision': 'a' * 40, 'graphHash': common.canonical_hash(self.records),
                        'policyHash': common.canonical_hash(CFG), 'parents': self.parents,
                        'rationale': 'Review all concurrent history and fresh complete evidence.', 'disposition': 'accepted'}
        self.value = self.record(self.request['rationale'], self.parents)
        self.value['payload']['recovery'] = deepcopy(self.request)

    def record(self, rationale, parents=None):
        return {'schema': 1, 'kind': 'security-findings', 'payload': {
            'disposition': 'accepted', 'rationale': rationale, 'supersedes': parents or [],
            'profiles': {p: recovery.normalize_findings(s, p) for p, s in self.native['profiles'].items()},
            'securityContexts': common.security_contexts(self.native),
            'packet': {'reference': common.packets.REGISTRY + '@sha256:' + 'b' * 64,
                       'sha256': 'c' * 64, 'producer': deepcopy(self.producer)}}}

    def guards(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        mocks = {}
        for name, target, kwargs in [
            ('ledger', 'common.ledger', {'return_value': ('a' * 40, self.records)}),
            ('main', 'common.main_revision', {'return_value': 'a' * 40}),
            ('policy', 'common.authority.document_at', {'return_value': CFG}),
            ('rules', 'common.required_check', {}),
            ('history', 'common.historical_provenance', {}),
            ('live', 'common.authorize', {}),
            ('proof', 'security_recovery.evidence', {})]:
            mocks[name] = stack.enter_context(patch(target, **kwargs))
        return mocks

    def bind(self):
        self.request['graphHash'] = common.canonical_hash(self.records)

    def test_complete_set_authenticates_each_packet_and_live_leaf_without_selection(self):
        mocks = self.guards()
        leaves = recovery.validate(CFG, self.request)
        self.assertEqual(sorted(leaves), self.parents)
        self.assertEqual(mocks['proof'].call_count, 3)
        self.assertEqual(mocks['live'].call_count, 2)
        self.assertEqual({common.canonical_hash(c.args[1]) for c in mocks['proof'].call_args_list}, set(self.records))
        self.assertNotEqual(self.one['payload']['packet'], self.two['payload']['packet'])
        # Ordinary admission and reconciliation remain fail-closed.
        with self.assertRaisesRegex(ValueError, 'Ambiguous concurrent'):
            common.active_security(CFG, self.records)
        with patch.object(reconciliation, 'ledger', return_value=('a' * 40, self.records)), \
                patch.object(reconciliation, 'scans') as scans:
            with self.assertRaisesRegex(ValueError, 'Ambiguous concurrent'):
                reconciliation.reconcile(CFG, None, None, 'security-findings', '.', 'ordinary')
            scans.assert_not_called()

    def test_request_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        self.assertEqual(recovery.load_request(json.dumps(self.request)), self.request)
        text = json.dumps(self.request)
        with self.assertRaisesRegex(ValueError, 'Duplicate recovery'):
            recovery.load_request(text[:-1] + ', "schema": 1}')
        with self.assertRaisesRegex(ValueError, 'Nonfinite recovery'):
            recovery.load_request(text.replace('"schema": 1', '"schema": NaN'))

    def test_request_shape_missing_duplicate_unsorted_and_extra_fields(self):
        self.guards()
        cases = [dict(self.request, parents=self.parents[:1]), dict(self.request, parents=self.parents * 2),
                 dict(self.request, parents=self.parents[::-1]), dict(self.request, waiver=True),
                 dict(self.request, rationale=' '), dict(self.request, disposition='revoked'),
                 dict(self.request, schema=True)]
        for key in self.request:
            cases.append({k: v for k, v in self.request.items() if k != key})
        for request in cases:
            with self.subTest(request=request), self.assertRaises(ValueError):
                recovery.validate(CFG, request)

    def test_omitted_or_extra_parent_rejected_even_with_valid_shape(self):
        mocks = self.guards()
        for parents in [sorted([self.parents[0], self.parent_hash]), sorted(self.parents + [self.parent_hash])]:
            with self.assertRaisesRegex(ValueError, 'complete current active parent'):
                recovery.validate(CFG, dict(self.request, parents=parents))
        mocks['proof'].assert_not_called()

    def test_changed_graph_policy_rules_and_concurrent_leaf_rejected(self):
        mocks = self.guards()
        with self.assertRaisesRegex(ValueError, 'snapshot changed'):
            recovery.validate(CFG, dict(self.request, graphHash='f' * 64))
        with self.assertRaisesRegex(ValueError, 'policy snapshot'):
            recovery.validate(CFG, dict(self.request, policyHash='f' * 64))
        mocks['policy'].return_value = dict(CFG, enabled=True)
        with self.assertRaisesRegex(ValueError, 'current policy changed'):
            recovery.validate(CFG, self.request)
        mocks['policy'].return_value = CFG
        mocks['rules'].side_effect = ValueError('rules changed')
        with self.assertRaisesRegex(ValueError, 'rules changed'):
            recovery.validate(CFG, self.request)
        mocks['rules'].side_effect = None
        added = self.record('concurrent new leaf')
        self.records[common.canonical_hash(added)] = added
        with self.assertRaisesRegex(ValueError, 'graph snapshot changed'):
            recovery.validate(CFG, self.request)
        self.bind()  # Rebinding the graph alone cannot omit the new parent.
        with self.assertRaisesRegex(ValueError, 'complete current active parent'):
            recovery.validate(CFG, self.request)

    def test_unequal_findings_contexts_and_nonaccepted_leaf_rejected(self):
        self.guards()
        changed_context = context()
        changed_context['tcpPorts'].append(8443)
        for field, value in [('profiles', {'maestro': []}),
                             ('securityContexts', {'maestro': changed_context}),
                             ('securityContexts', {'unexpected': {}}),
                             ('disposition', 'rejected')]:
            original = deepcopy(self.two['payload'][field])
            self.two['payload'][field] = value
            self.bind()
            with self.subTest(field=field), self.assertRaises(ValueError):
                recovery.validate(CFG, self.request)
            self.two['payload'][field] = original

    def test_cycles_and_missing_historical_parent_rejected(self):
        self.guards()
        for parents in [[self.parents[0]], ['f' * 64]]:
            self.parent['payload']['supersedes'] = parents
            self.bind()
            with self.assertRaisesRegex(ValueError, 'Cyclic|Invalid supersession'):
                recovery.validate(CFG, self.request)

    def test_forged_historical_provenance_packet_and_revoked_authority_fail(self):
        mocks = self.guards()
        for key in ['history', 'proof', 'live']:
            mocks[key].side_effect = ValueError('forged or revoked ' + key)
            with self.subTest(boundary=key), self.assertRaisesRegex(ValueError, 'forged or revoked'):
                recovery.validate(CFG, self.request)
            mocks[key].side_effect = None

    def test_final_main_read_rejects_race(self):
        mocks = self.guards()
        mocks['main'].return_value = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'snapshot changed'):
            recovery.validate(CFG, self.request)

    def test_proposal_binds_all_parents_rationale_disposition_and_fresh_scope(self):
        self.guards()
        self.assertEqual(recovery.proposal(CFG, self.value), 'a' * 40)
        for field, value in [('supersedes', [self.parents[0]]), ('rationale', 'other'),
                             ('disposition', 'rejected'), ('profiles', {'maestro': []})]:
            changed = deepcopy(self.value)
            changed['payload'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                recovery.proposal(CFG, changed)

    def test_historical_evidence_checks_producer_attestation_findings_and_context(self):
        # Use the actual packet-proof validator, with only transport/native crypto mocked.
        with patch.object(recovery.packets, 'fetch', return_value={'producer': self.producer}), \
                patch.object(common, 'scans', return_value=self.native) as scans:
            recovery.evidence(CFG, self.one)
            scans.assert_called_once()
            self.assertTrue(scans.call_args.kwargs['allow_expired'])
            for field, value in [('profiles', {'maestro': []}), ('securityContexts', {'bad': {}}),
                                 ('packet', dict(self.one['payload']['packet'], producer={}))]:
                changed = deepcopy(self.one)
                changed['payload'][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    recovery.evidence(CFG, changed)
        with patch.object(recovery.packets, 'fetch', return_value={'producer': self.producer}), \
                patch.object(common, 'scans', side_effect=ValueError('forged attestation')):
            with self.assertRaisesRegex(ValueError, 'forged attestation'):
                recovery.evidence(CFG, self.one)

    def test_packet_validation_requires_fresh_scan_and_final_complete_graph(self):
        mocks = self.guards()
        with patch.object(reconciliation.packets, 'fetch', return_value={'producer': self.producer}), \
                patch.object(reconciliation, 'scans', return_value=self.native) as scans, \
                patch.object(common, 'verify_producer') as producer:
            reconciliation.validate_proposal_packet(self.value, CFG)
            self.assertFalse(scans.call_args.kwargs['allow_expired'])
            self.assertEqual(mocks['ledger'].call_count, 2)
            self.assertEqual(mocks['live'].call_count, 4)
            self.assertTrue(producer.call_args.kwargs['require_main'])
            mocks['ledger'].side_effect = [('a' * 40, self.records), ('b' * 40, self.records)]
            with self.assertRaisesRegex(ValueError, 'snapshot changed'):
                reconciliation.validate_proposal_packet(self.value, CFG)
            mocks['ledger'].side_effect = None
            mocks['live'].side_effect = [None, None, ValueError('revoked during bytes')]
            with self.assertRaisesRegex(ValueError, 'revoked during bytes'):
                reconciliation.validate_proposal_packet(self.value, CFG)

    def test_expired_fresh_scan_and_untrusted_producer_fail(self):
        native = deepcopy(self.native)
        native['expiresAt'] = native['scannedAt']
        with patch.object(common, 'verify_producer') as producer:
            with self.assertRaisesRegex(ValueError, 'observation-expired'):
                recovery.fresh(CFG, native)
            producer.assert_not_called()
        with patch.object(common, 'verify_producer', side_effect=ValueError('untrusted producer')):
            with self.assertRaisesRegex(ValueError, 'untrusted producer'):
                recovery.fresh(CFG, self.native)

    def test_reconcile_never_covers_implicitly_and_binds_request_in_new_proposal(self):
        self.guards()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'scans.json'
            path.write_text(json.dumps(self.native))
            with patch.object(reconciliation, 'scans', return_value=self.native), \
                    patch.object(common, 'verify_producer'), \
                    patch.object(reconciliation.packets, 'push', return_value=self.value['payload']['packet']), \
                    patch.object(reconciliation, 'validate_proposal_packet'), \
                    patch.object(reconciliation, 'propose', side_effect=lambda cfg, p: p):
                result = reconciliation.reconcile(CFG, path, None, 'security-findings', temporary,
                                                  self.request['rationale'], recovery=self.request)
            self.assertEqual(result['payload']['supersedes'], self.parents)
            self.assertEqual(result['payload']['recovery'], self.request)
            self.assertEqual(result['payload']['profiles'], self.one['payload']['profiles'])
            self.assertEqual(len(self.records), 3)

    def test_protected_check_requires_fresh_human_review_and_exact_queue_ledger(self):
        value = deepcopy(self.value)
        snapshot_sha = 'e' * 40
        value['payload']['recovery']['mainRevision'] = snapshot_sha
        api = CheckGitHub()
        api.proposal = value
        path = common.authority.proposal_path(value)
        api.files = [{'filename': path, 'status': 'added'}]
        old = {'path': 'automation/decisions/security/' + self.parent_hash + '.json',
               'type': 'blob', 'mode': '100644', 'sha': 'f' * 40}
        new = {'path': path, 'type': 'blob', 'mode': '100644', 'sha': 'd' * 40}
        folder = {'path': 'automation/decisions/security', 'type': 'tree', 'mode': '040000', 'sha': '1' * 40}
        api.head_tree = {'truncated': False, 'tree': [old, new, dict(folder, sha='2' * 40)]}
        api.queue_tree = deepcopy(api.head_tree)
        def transport(endpoint):
            if endpoint == f'repos/{REPO}/git/trees/{snapshot_sha}?recursive=1':
                return {'truncated': False, 'tree': [old, folder]}
            return api(endpoint)
        with patch.object(checked, 'validate_proposal_packet'), \
                patch.object(checked, 'main_revision', return_value=snapshot_sha), \
                patch.object(recovery, 'proposal') as final:
            self.assertEqual(checked.check_pr(REPO, 7, BOT, MERGE, transport)['status'], 'authorized')
            final.assert_called_once()
            self.assertFalse(final.call_args.kwargs['verify_packets'])
            api.queue_tree['tree'].append(dict(old, path='automation/decisions/security/' + 'f' * 64 + '.json'))
            with self.assertRaisesRegex(ValueError, 'Recovery queue graph differs'):
                checked.check_pr(REPO, 7, BOT, MERGE, transport)
            api.queue_tree = deepcopy(api.head_tree)
            api.reviews = []
            with self.assertRaisesRegex(ValueError, 'Super Admin'):
                checked.check_pr(REPO, 7, BOT, MERGE, transport)
            api.reviews = [{'id': 10, 'state': 'APPROVED', 'commit_id': HEAD,
                            'user': {'id': 1, 'login': 'maintainer', 'type': 'User'}}]
            final.side_effect = ValueError('concurrent final leaf')
            with self.assertRaisesRegex(ValueError, 'concurrent final leaf'):
                checked.check_pr(REPO, 7, BOT, MERGE, transport)

    def test_recovery_proposals_are_drafts_and_never_call_queue_transport(self):
        pull = {'number': 321, 'user': {'login': CFG['botLogin'], 'type': 'Bot'}}
        with patch.object(reconciliation.authority, 'collection', return_value=[]), \
                patch.object(reconciliation.authority, 'github_api', side_effect=[
                    {'object': {'sha': 'a' * 40}}, {'tree': {'sha': 'b' * 40}}]), \
                patch.object(recovery, 'proposal'), \
                patch.object(reconciliation, 'api_write', side_effect=[{'sha': 'c' * 40}, {'sha': 'd' * 40}, {}, pull]) as write, \
                patch.object(reconciliation, 'queue_proposal') as queue:
            result = reconciliation.propose(CFG, self.value)
            self.assertEqual(result['status'], 'awaiting-review')
            self.assertTrue(write.call_args_list[-1].args[1]['draft'])
            queue.assert_not_called()


if __name__ == '__main__':
    unittest.main()
