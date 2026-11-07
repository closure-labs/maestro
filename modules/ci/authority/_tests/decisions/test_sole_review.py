#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact-head self-review is code authority, never findings acceptance."""
import copy
import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('sole_fixture', Path(__file__).with_name('test_check.py'))
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
mod, check, HEAD = f.mod.authority, f.mod, f.HEAD
REPO = 'closure-labs/maestro'

class API(f.GitHub):
    def __init__(self):
        super().__init__()
        self.user = dict(id=52590374, login='declarative-dale', type='User')
        self.pr['user'] = self.user.copy()
        self.members = [self.user.copy()]
        self.roles = {'declarative-dale': 'admin'}
        self.collaborators = [dict(self.user, role_name='admin')]
        self.roster_calls = 0
        self.roster_failure = self.join_on_recheck = False
        self.reviews = [dict(id=10, state='COMMENTED', commit_id=HEAD,
                            user=self.user.copy(), body='/maestro self-review ' + HEAD)]
        self.files = [dict(filename='modules/ci/security/policy.nix', status='modified')]
        self.pr['base']['repo']['full_name'] = REPO
        self.pr['head']['repo']['full_name'] = REPO
    def __call__(self, endpoint):
        if '/collaborators?affiliation=all' in endpoint:
            self.roster_calls += 1
            if self.roster_failure: raise mod.AuthorityError('Forbidden')
            rows = copy.deepcopy(self.collaborators)
            if self.join_on_recheck and self.roster_calls > 1:
                rows.append(dict(id=2, login='other', type='User', role_name='maintain'))
            return rows
        return super().__call__(endpoint.replace('repos/' + REPO + '/', 'repos/' + f.REPO + '/'))

class SoleReview(unittest.TestCase):
    def approve(self, api):
        return mod.approval(api, REPO, 7, HEAD, allow_sole_self_review=True)
    def test_exact_self_review(self):
        self.assertEqual(self.approve(API())['id'], 10)
        self.assertEqual(check.check_pr(REPO, 7, 'cl-decider[bot]', github=API())['status'], 'authorized')
    def test_proposal_route_remains_independent(self):
        with self.assertRaises(mod.HumanDecisionRequired): mod.approval(API(), REPO, 7, HEAD)
        api=API(); api.files=[dict(filename=mod.proposal_path(f.fixtures.PROPOSAL),status='added')]
        with self.assertRaises(mod.HumanDecisionRequired): check.check_pr(REPO,7,'cl-decider[bot]',github=api)
    def test_wrong_marker_head_state_and_identity(self):
        mutations = [lambda a:a.reviews[0].update(commit_id='b'*40),
            lambda a:a.reviews[0].update(body='/maestro self-review '+'b'*40),
            lambda a:a.reviews[0].update(body='approve'),
            lambda a:a.reviews[0].update(state='APPROVED'),
            lambda a:a.pr.update(user=dict(a.user,id=123)),
            lambda a:a.reviews[0].update(user=dict(a.user,id=123)),
            lambda a:a.reviews[0].update(user=dict(a.user,type='Bot')),
            lambda a:a.roles.update({'declarative-dale':'write'}),
            lambda a:a.memberships.update({'declarative-dale':dict(state='pending',role='member')})]
        for mutation in mutations:
            api=API();mutation(api)
            with self.subTest(mutation=mutation),self.assertRaises(mod.AuthorityError):self.approve(api)
    def test_revocation(self):
        for state,body in [('COMMENTED','/maestro revoke-self-review '+HEAD),('DISMISSED',''),('CHANGES_REQUESTED','')]:
            api=API();api.reviews.append(dict(api.reviews[0],id=11,state=state,body=body))
            with self.subTest(state=state),self.assertRaises(mod.HumanDecisionRequired):self.approve(api)
    def test_bad_or_expanded_roster(self):
        for row in [dict(id=2,login='other',type='User',role_name=r) for r in ['maintain','admin','custom',None]] + [dict(id=52590374,login='declarative-dale',type='User',role_name='admin')]:
            api=API();api.collaborators.append(row)
            with self.subTest(row=row),self.assertRaises(mod.AuthorityError):self.approve(api)
        for field,value in [('collaborators',[]),('roster_failure',True),('join_on_recheck',True)]:
            api=API();setattr(api,field,value)
            with self.subTest(field=field),self.assertRaises(mod.AuthorityError):self.approve(api)
    def test_team_expansion(self):
        api=API();api.members.append(dict(id=2,login='other',type='User'))
        with self.assertRaises(mod.AuthorityError):self.approve(api)
    def test_other_repository(self):
        with self.assertRaises(mod.HumanDecisionRequired):mod.approval(API(),f.REPO,7,HEAD,allow_sole_self_review=True)
    def test_non_author_commands_do_not_erase_independent_objection(self):
        for command in ('self-review', 'revoke-self-review'):
            api=API(); api.pr['user']=dict(id=3,login='author',type='User')
            other=dict(id=2,login='other',type='User')
            api.members.append(other); api.roles['other']='maintain'
            api.reviews=[dict(id=10,state='APPROVED',commit_id=HEAD,user=api.user),
                dict(id=11,state='CHANGES_REQUESTED',commit_id=HEAD,user=other),
                dict(id=12,state='COMMENTED',commit_id=HEAD,user=other,
                     body='/maestro '+command+' '+HEAD)]
            with self.subTest(command=command),self.assertRaises(mod.HumanDecisionRequired):self.approve(api)
    def test_unrelated_comment_does_not_revoke(self):
        api=API();api.reviews.append(dict(api.reviews[0],id=11,body='Thanks'))
        self.assertEqual(self.approve(api)['id'],10)
    def test_login_identity_mismatch(self):
        for target in ('author','reviewer'):
            api=API()
            if target=='author':api.pr['user']=dict(api.user,login='other')
            else:api.reviews[0]['user']=dict(api.user,login='other')
            with self.subTest(target=target),self.assertRaises(mod.AuthorityError):self.approve(api)
    def test_mixed_or_renamed_proposal_disables_exception(self):
        proposal=mod.proposal_path(f.fixtures.PROPOSAL)
        for row in [dict(filename=proposal,status='added'),
                    dict(filename='docs/moved.json',previous_filename=proposal,status='renamed')]:
            api=API();api.files.append(row);api.pr['changed_files']=2
            with self.subTest(row=row),self.assertRaises(mod.AuthorityError):
                check.check_pr(REPO,7,'cl-decider[bot]',github=api)
    def test_access_changes_between_check_evaluations(self):
        api=API(); reads=0
        def changing(endpoint):
            nonlocal reads
            if '/pulls/7/reviews?' in endpoint:
                reads+=1
                if reads==2:api.roles['declarative-dale']='read'
            return api(endpoint)
        with self.assertRaises(mod.AuthorityError):check.check_pr(REPO,7,'cl-decider[bot]',github=changing)
    def test_paginated_roster(self):
        api=API()
        def pages(endpoint):
            if '/collaborators?affiliation=all' not in endpoint:return api(endpoint)
            if endpoint.endswith('page=1'):
                return api.collaborators+[dict(id=100+i,login='reader'+str(i),type='User',role_name='read') for i in range(99)]
            return [dict(id=2,login='other',type='User',role_name='maintain')]
        with self.assertRaises(mod.HumanDecisionRequired):mod.approval(pages,REPO,7,HEAD,allow_sole_self_review=True)

if __name__=='__main__':unittest.main()
