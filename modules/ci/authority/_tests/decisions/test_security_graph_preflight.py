# SPDX-License-Identifier: Apache-2.0
"""Cheap graph rejection cannot replace historical provenance or live authority."""
from copy import deepcopy
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / 'modules/ci/authority/_source/decisions'))
import common
import test_authority as authority_fixture
import test_verification_context as gate_fixture

CFG = {'repository': 'closure-labs/maestro', 'botLogin': 'cl-decider[bot]', 'profiles': ['maestro']}


def decision(parents=(), rationale='Reviewed scope', kind='security-findings', disposition='accepted'):
    return {'schema': 1, 'kind': kind, 'payload': {
        'profiles': {'maestro': []}, 'disposition': disposition, 'rationale': rationale,
        'supersedes': list(parents), 'packet': {
            'reference': common.packets.REGISTRY + '@sha256:' + 'a' * 64, 'sha256': 'b' * 64}}}


def chain(length, fork=False):
    records, previous = {}, []
    for index in range(length):
        value = decision(previous, 'Reviewed scope '+str(index))
        digest = common.canonical_hash(value)
        records[digest] = value
        previous = [digest]
    if fork:
        parents = records[previous[0]]['payload']['supersedes']
        value = decision(parents, 'Concurrent scope requiring reconciliation')
        records[common.canonical_hash(value)] = value
    return records


class GraphAPI:
    """Real native provenance/authority logic over deterministic GitHub responses."""
    def __init__(self, records):
        self.calls, self.by_path, self.by_number, self.by_merge = [], {}, {}, {}
        for index, proposal in enumerate(records.values()):
            number, merge = index + 7, f'{index + 7:040x}'
            remote = authority_fixture.GitHub()
            remote.proposal = deepcopy(proposal)
            remote.pr.update(number=number, merge_commit_sha=merge)
            remote.pr['user']['login'] = CFG['botLogin']
            remote.pr['head']['repo']['full_name'] = CFG['repository']
            remote.pr['base']['repo']['full_name'] = CFG['repository']
            remote.timeline[0]['commit_id'] = merge
            path = common.authority.proposal_path(proposal)
            remote.files = [{'filename': path, 'status': 'added'}]
            self.by_path[path] = remote
            self.by_number[number] = remote
            self.by_merge[merge] = remote
        self.current = next(iter(self.by_number.values()), None)

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        if '/commits?path=' in endpoint:
            path = parse_qs(urlsplit(endpoint).query)['path'][0]
            self.current = self.by_path[path]
            return [{'sha': self.current.pr['merge_commit_sha']}]
        for merge, remote in self.by_merge.items():
            if '/commits/'+merge+'/pulls?' in endpoint:
                self.current = remote
                return [deepcopy(remote.pr)]
        match = re.search(r'/(?:pulls|issues)/([0-9]+)', endpoint)
        if match:
            self.current = self.by_number[int(match[1])]
        if '/contents/' in endpoint:
            path = endpoint.split('/contents/', 1)[1].split('?', 1)[0]
            self.current = self.by_path[path]
        # The shared authority fixture's route uses PR #7 and its original repo;
        # returned PR metadata is still the actual Maestro identity above.
        internal = endpoint.replace('repos/'+CFG['repository'], 'repos/'+authority_fixture.REPO)
        internal = re.sub(r'/(pulls|issues)/[0-9]+', r'/\1/7', internal)
        return self.current(internal)


class SecurityGraphPreflight(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        environment = patch.dict(os.environ, {'RUNNER_TEMP': temporary.name,
            'MAESTRO_PACKET_METADATA_REUSE_ENABLED': 'false', 'MAESTRO_PACKET_METADATA_BATCH_ENABLED': 'false',
            'MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED': 'false'})
        environment.start()
        self.addCleanup(environment.stop)

    def test_ambiguous_graph_with_ten_superseded_parents_makes_zero_provenance_gets(self):
        records = chain(11, fork=True)
        api = GraphAPI(records)
        with patch.object(common, 'historical_provenance', wraps=common.historical_provenance) as history, \
                patch.object(common, 'authorize', wraps=common.authorize) as live:
            with self.assertRaisesRegex(ValueError, 'Ambiguous concurrent'):
                common.active_security(CFG, records, api)
        self.assertEqual(api.calls, [])
        history.assert_not_called()
        live.assert_not_called()

    def test_cycle_is_rejected_even_when_one_separate_leaf_looks_valid(self):
        first, second = decision(['b' * 64]), decision(['a' * 64])
        records = {'a' * 64: first, 'b' * 64: second, 'c' * 64: decision()}
        api = GraphAPI(records)
        with self.assertRaisesRegex(ValueError, 'Cyclic'):
            common.active_security(CFG, records, api)
        self.assertEqual(api.calls, [])

    def test_malformed_unknown_duplicate_or_self_parent_rejects_before_history(self):
        for parents in (None, 'not-a-list', ['f' * 64], ['a' * 64], ['f' * 64, 'f' * 64]):
            value = decision()
            value['payload']['supersedes'] = parents
            records = {'a' * 64: value}
            api = GraphAPI(records)
            with self.subTest(parents=parents), self.assertRaises(ValueError):
                common.active_security(CFG, records, api)
            self.assertEqual(api.calls, [])

    def test_valid_chain_retains_every_historical_proof_and_live_leaf_review(self):
        records = chain(4)
        api = GraphAPI(records)
        with patch.object(common, 'historical_provenance', wraps=common.historical_provenance) as history, \
                patch.object(common, 'authorize', wraps=common.authorize) as live:
            digest, selected = common.active_security(CFG, records, api)
        self.assertEqual(digest, next(reversed(records)))
        self.assertEqual(selected, records[digest])
        self.assertEqual(history.call_count, 3)
        live.assert_called_once()
        self.assertEqual(sum('/reviews?' in endpoint for endpoint in api.calls), 1)
        self.assertGreater(len(api.calls), 0)

    def test_passing_shape_cannot_hide_forged_parent_provenance(self):
        records = chain(2)
        api = GraphAPI(records)
        api.by_number[7].files[0]['filename'] = 'unexpected-history.json'
        with patch.object(common, 'authorize', wraps=common.authorize) as live:
            with self.assertRaisesRegex(ValueError, 'unexpected'):
                common.active_security(CFG, records, api)
        live.assert_not_called()
        self.assertGreater(len(api.calls), 0)

    def test_authenticate_false_still_verifies_history_and_grants_no_leaf_authority(self):
        records = chain(2)
        api = GraphAPI(records)
        with patch.object(common, 'authorize', side_effect=AssertionError('Live authority reached')):
            common.active_security(CFG, records, api, authenticate=False)
        self.assertGreater(len(api.calls), 0)
        self.assertFalse(any('/reviews?' in endpoint for endpoint in api.calls))
        api.by_number[7].files.clear()
        with self.assertRaises(ValueError):
            common.active_security(CFG, records, api, authenticate=False)

    def test_revoked_leaf_remains_authentic_but_cannot_grant_risk_acceptance(self):
        parent = decision()
        digest = common.canonical_hash(parent)
        revoke = decision([digest], kind='security-revocation', disposition='revoked')
        records = {digest: parent, common.canonical_hash(revoke): revoke}
        api = GraphAPI(records)
        self.assertEqual(common.active_security(CFG, records, api)[1]['payload']['disposition'], 'revoked')
        with self.assertRaisesRegex(ValueError, 'Current human risk acceptance required'):
            common.admission(CFG, {'profiles': {'maestro': {}}}, records, api)

    def test_changed_live_review_still_blocks_otherwise_valid_graph(self):
        records = chain(2)
        api = GraphAPI(records)
        api.by_number[8].reviews[0]['state'] = 'DISMISSED'
        with self.assertRaises(common.authority.HumanDecisionRequired):
            common.active_security(CFG, records, api)

    def test_empty_graph_is_no_selection_and_never_an_acceptance(self):
        self.assertEqual(common.security_graph(CFG, {}), (None, None))
        with self.assertRaisesRegex(ValueError, 'Current human risk acceptance required'):
            common.admission(CFG, {'profiles': {'maestro': {}}}, {})

    def test_concurrent_graph_addition_still_blocks_final_gate_refresh(self):
        for reuse in (False, True):
            api = gate_fixture.ObservedAPI()
            added = []
            def mutate(endpoint):
                if '/git/trees/' in endpoint and api.product_review_reads and not added:
                    fork = deepcopy(api.risk)
                    fork['payload']['rationale'] = 'Concurrent decision after initial graph passed'
                    path = common.authority.proposal_path(fork)
                    api.records[path] = fork
                    added.append(path)
            api.mutate = mutate
            with self.subTest(reuse=reuse), self.assertRaises(ValueError):
                gate_fixture.Context.invoke(self, api, reuse)
            self.assertEqual(len(added), 1)


if __name__ == '__main__':
    unittest.main()
