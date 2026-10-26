# SPDX-License-Identifier: Apache-2.0
"""Gate-local reuse must preserve live revocation and final freshness."""
from copy import deepcopy
import datetime as dt
import os
import unittest
from unittest.mock import patch

import test_product_authority as fixture
import test_authority as authority_fixture
import common
from verification_context import VerificationContext


class ObservedAPI(fixture.PublicationAPI):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.mutate = lambda endpoint: None
        self.main_override = None
        self.rules_override = None
        self.approve_product()

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        self.mutate(endpoint)
        if '/rules/branches/main' in endpoint and self.rules_override is not None:
            return self.rules_override
        if endpoint.endswith('/git/ref/heads/main') and self.main_override:
            return {'object': {'sha': self.main_override}}
        return super().__call__(endpoint)


class Context(unittest.TestCase):
    def invoke(self, api, enabled=True):
        with patch.dict(os.environ, {'MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED': str(enabled).lower()}):
            return fixture.ProductAuthority.invoke(self, api, 'release')

    def test_same_decision_fewer_requests_and_live_reviews_twice(self):
        old, new = ObservedAPI(), ObservedAPI()
        self.assertEqual(self.invoke(old, False), self.invoke(new))
        self.assertLess(len(new.calls), len(old.calls))
        self.assertEqual(new.product_review_reads, 2)
        histories = [x for x in new.calls if '/commits?path=' in x]
        self.assertEqual(len(histories), 2)
        self.assertTrue(all('&sha=main&' not in x for x in histories))
        team = 'orgs/closure-labs/teams/super-admins'
        self.assertEqual(new.calls.count(team), 4)  # beginning/end of each live pass
        self.assertGreaterEqual(sum('/collaborators/maintainer/permission' in x for x in new.calls), 4)

    def test_dismissed_product_review_blocks_final_refresh(self):
        api = ObservedAPI()
        api.revoke_product_on_final_check = True
        with self.assertRaises(common.authority.HumanDecisionRequired):
            self.invoke(api)

    def test_lost_membership_permission_and_identity_block_refresh(self):
        for change in ('membership', 'permission', 'identity', 'head'):
            api = ObservedAPI()
            def mutate(endpoint):
                if '/pulls/8/reviews?' in endpoint and api.product_review_reads == 1:
                    if change == 'membership':
                        api.github.memberships['maintainer'] = {'state': 'pending', 'role': 'member'}
                    elif change == 'permission':
                        api.github.roles['maintainer'] = 'read'
                    elif change == 'identity':
                        api.product_github.reviews[0]['user']['id'] = 99
                    else:
                        api.product_github.pr['head']['sha'] = 'f' * 40
            api.mutate = mutate
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.invoke(api)

    def test_main_policy_and_ledger_changes_during_gate_fail(self):
        for field in ('main', 'policy', 'ledger'):
            api = ObservedAPI()
            def mutate(endpoint):
                if '/git/trees/' in endpoint and api.product_review_reads:
                    if field == 'main':
                        api.main_override = 'f' * 40
                    elif field == 'policy':
                        api.policy['enabled'] = False
                    else:
                        api.records.pop(api.path, None)
            api.mutate = mutate
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.invoke(api)

    def test_membership_inventory_is_reread_at_end_of_pass(self):
        api = ObservedAPI()
        def mutate(endpoint):
            if '/pulls/8/reviews?' in endpoint and api.product_review_reads == 1:
                api.github.members = []
        api.mutate = mutate
        with self.assertRaisesRegex(ValueError, 'membership-changed'):
            self.invoke(api)

    def test_final_rules_removal_and_changed_verifier_fail(self):
        api = ObservedAPI()
        def mutate(endpoint):
            if '/rules/branches/main' in endpoint and api.product_review_reads:
                api.rules_override = []
        api.mutate = mutate
        with self.assertRaisesRegex(ValueError, 'not enforced'):
            self.invoke(api)
        context = VerificationContext()
        context.bind(api.policy, 'a' * 40, api.records, api.product)
        with patch('verification_context.verifier_version', return_value='changed'), \
                self.assertRaisesRegex(ValueError, 'verifier-changed'):
            context.check(api.policy, 'a' * 40, api.records, api.product)

    def test_complete_binding_changes_fail_closed_and_discard(self):
        for field, reason in [('repository', 'repository'), ('revision', 'main'), ('policy', 'policy'),
                              ('records', 'ledger'), ('product', 'product')]:
            api = ObservedAPI()
            cfg, records, product = api.policy, api.records, api.product
            context = VerificationContext()
            context.bind(cfg, 'a' * 40, records, product)
            cfg, records, product = deepcopy(cfg), deepcopy(records), deepcopy(product)
            revision = 'a' * 40
            if field == 'repository': cfg['repository'] = 'closure-labs/another'
            if field == 'revision': revision = 'b' * 40
            if field == 'policy': cfg['enabled'] = False
            if field == 'records': records.clear()
            if field == 'product': product['assets']['new'] = 'f' * 64
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, reason + '-changed'):
                context.check(cfg, revision, records, product)
            self.assertTrue(context.invalid)
            self.assertEqual(context.graphs, {})

    def test_history_and_graph_validated_once_but_live_authority_repeated(self):
        api = ObservedAPI()
        parent = deepcopy(api.risk)
        parent['payload']['packet']['reference'] = common.packets.REGISTRY + '@sha256:' + 'a' * 64
        parent_hash = common.canonical_hash(parent)
        child = deepcopy(parent)
        child['payload']['supersedes'] = [parent_hash]
        child_hash = common.canonical_hash(child)
        records = {parent_hash: parent, child_hash: child}
        context = VerificationContext()
        context.bind(api.policy, 'a' * 40, records, api.product)
        with patch.object(common, 'historical_provenance') as historical, \
                patch.object(common, 'authorize') as live, \
                patch.object(common, 'security_graph', wraps=common.security_graph) as graph:
            for _ in range(2):
                digest, selected = common.active_security(api.policy, records, context=context)
                self.assertEqual(digest, child_hash)
            self.assertEqual(graph.call_count, 1)
            self.assertEqual(historical.call_count, 1)
            self.assertEqual(live.call_count, 2)
        records[parent_hash]['payload']['disposition'] = 'revoked'
        with self.assertRaisesRegex(ValueError, 'inputs-changed'):
            common.active_security(api.policy, records, context=context)

    def test_historical_provenance_reused_but_active_pr_responses_remain_live(self):
        remote = authority_fixture.GitHub()
        cfg = {'repository': authority_fixture.REPO, 'botLogin': authority_fixture.BOT}
        proposal = deepcopy(remote.proposal)
        context = VerificationContext()
        context.bind(cfg, authority_fixture.MAIN, {common.canonical_hash(proposal): proposal}, None)
        calls = []
        def api(endpoint):
            calls.append(endpoint)
            if '/commits?path=' in endpoint:
                self.assertIn('&sha=' + authority_fixture.MAIN + '&', endpoint)
                return [{'sha': authority_fixture.MERGE}]
            if '/commits/' + authority_fixture.MERGE + '/pulls?' in endpoint:
                return [deepcopy(remote.pr)]
            return remote(endpoint)
        first = common.historical_provenance(cfg, proposal, api, context)
        before = len(calls)
        self.assertEqual(common.historical_provenance(cfg, proposal, api, context), first)
        self.assertEqual(len(calls), before)
        self.assertEqual(first['status'], 'historical-provenance')
        self.assertIsNone(first['reviewId'])
        common.authorize(cfg, proposal, api, context=context)
        remote.reviews[0]['state'] = 'DISMISSED'
        with self.assertRaises(common.authority.HumanDecisionRequired):
            common.authorize(cfg, proposal, api, context=context)
        self.assertGreater(len(calls), before)

    def test_gate_discards_context_on_success_and_failure(self):
        for revoked in (False, True):
            api = ObservedAPI()
            api.revoke_product_on_final_check = revoked
            context = VerificationContext()
            with patch.object(common, 'VerificationContext', return_value=context):
                if revoked:
                    with self.assertRaises(ValueError): self.invoke(api)
                else:
                    self.invoke(api)
            self.assertTrue(context.invalid)
            self.assertEqual(context.graphs, {})
            self.assertEqual(context.documents, {})
            with self.assertRaises(ValueError): context.repository(api.policy['repository'])

    def test_context_cannot_authorize_another_gate(self):
        context = VerificationContext()
        api = ObservedAPI()
        context.bind(api.policy, 'a' * 40, api.records, api.product)
        with self.assertRaisesRegex(ValueError, 'already-used'):
            context.bind(api.policy, 'a' * 40, api.records, api.product)

    def test_expiry_during_authority_blocks_return(self):
        for field in ('observation', 'database'):
            api = ObservedAPI()
            real_clock = dt.datetime
            now = real_clock.now(dt.timezone.utc)
            if field == 'database':
                api.scan['profiles']['maestro']['database']['built'] = (now - dt.timedelta(hours=47)).isoformat()
                api.scan['expiresAt'] = (now + dt.timedelta(hours=4)).isoformat()
            class Clock(real_clock):
                @classmethod
                def now(cls, tz=None):
                    observed = real_clock.now(tz)
                    if api.product_review_reads >= 2:
                        if field == 'observation':
                            return common.timestamp(api.scan['expiresAt'])
                        return observed + dt.timedelta(hours=2)
                    return observed
            with self.subTest(field=field), patch.object(common.dt, 'datetime', Clock), \
                    self.assertRaisesRegex(ValueError, field + '-expired'):
                self.invoke(api)


if __name__ == '__main__':
    unittest.main()
