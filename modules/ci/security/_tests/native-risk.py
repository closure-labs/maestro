#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact human risk approval is distinct from routine code approval."""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('publication_fixture',Path(__file__).with_name('native-publication.py'))
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
pub=fixture.pub;risk=pub.risk
SHA='a'*40;HEAD='b'*40;MERGE='c'*40

def encoded(raw):return dict(encoding='base64',size=len(raw),content=base64.b64encode(raw).decode())

class Risk(unittest.TestCase):
    def setUp(self):
        self.case=fixture.Publication();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.root=self.case.case.root
        self.case.findings=[self.case.finding('high'),self.case.finding('critical','b')]
        self.bundle=self.case.bundle();self.bundle['binding']=self.case.case.binding
        self.bundle['normalizedFindings']=[dict(identity='x',severity='High'),dict(identity='y',severity='Critical')]
        self.files={'.github/CODEOWNERS':self.root/'owners'};self.files['.github/CODEOWNERS'].write_text('* @human\n')
        now=datetime.now(timezone.utc)
        self.record=dict(schemaVersion=1,kind=risk.KIND,repository='closure-labs/maestro',reviewPullRequest=209,
            createdAt=(now-timedelta(minutes=1)).isoformat(),expiresAt=(now+timedelta(days=1)).isoformat(),
            reason='Explicitly accept these fixture high and critical risks',evidence=['https://example.test/review'],
            scope=risk.scope(self.bundle,self.case.findings,self.files),
            acceptedRawFindings=risk.fingerprints(self.case.findings),
            acceptedNormalizedFindings=risk.fingerprints(self.bundle['normalizedFindings']))
        self.path=self.root/risk.PATH;self.path.parent.mkdir(parents=True);self.write()
        self.pr=dict(number=209,merged_at='2026-11-02T00:00:00Z',state='closed',changed_files=1,
            title='security: accept findings risk for fixture',base=dict(ref='main',repo=dict(full_name='closure-labs/maestro')),
            head=dict(sha=HEAD,repo=dict(full_name='closure-labs/maestro')),merge_commit_sha=MERGE,user=dict(id=10))
        self.reviews=[dict(id=30,state='APPROVED',commit_id=HEAD,body='Reviewed: accept the risks specified by this dedicated findings decision',
            user=dict(id=20,type='User',login='human'))]
        self.changed_files=[dict(filename=risk.PATH,status='added')]
        self.permission=dict(permission='write',user=dict(id=20))
    def write(self):self.path.write_text(json.dumps(self.record))
    def api(self,path):
        if path.startswith('contents/'+risk.PATH+'?ref='):return encoded(self.path.read_bytes())
        if path.startswith('contents/.github/CODEOWNERS?ref='):return encoded(self.files['.github/CODEOWNERS'].read_bytes())
        if path=='collaborators/human/permission':return self.permission
        if path=='pulls/209':return self.pr
        if path=='pulls/209/files?per_page=2':return self.changed_files
        if path==f'compare/{MERGE}...{SHA}':return dict(merge_base_commit=dict(sha=MERGE))
        if path=='pulls/209/reviews?per_page=100&page=1':return self.reviews
        return self.case.api(path)
    def accept(self):return risk.acceptance(self.bundle,self.case.findings,self.case.findings,self.bundle['normalizedFindings'],self.files,self.api,self.root)
    def test_independent_explicit_review_accepts_exact_high_critical_risk(self):
        state=self.accept();self.assertEqual(state['raw'],set(risk.fingerprints(self.case.findings)))
        self.assertEqual(state['proof']['reviewId'],30)
        risk.live(self.api,state,SHA)
        self.reviews[0]['body']='LGTM'
        self.assertEqual(self.accept()['proof']['reviewId'],30)
    def test_self_bot_wrong_head_or_nonowner_reject(self):
        for field,value in [('commit_id','f'*40),('state','DISMISSED')]:
            with self.subTest(field=field),patch.dict(self.reviews[0],{field:value}):
                with self.assertRaises(ValueError):self.accept()
        for change in [dict(id=10),dict(type='Bot'),dict(login='other')]:
            with self.subTest(change=change),patch.dict(self.reviews[0]['user'],change):
                with self.assertRaises(ValueError):self.accept()
    def test_later_revoked_or_changes_requested_review_rejects_even_out_of_order(self):
        state=self.accept()
        for status in ('DISMISSED','CHANGES_REQUESTED'):
            later=dict(self.reviews[0],id=31,state=status)
            with patch.object(self,'reviews',[later,*self.reviews]):
                with self.assertRaises(ValueError):risk.live(self.api,state,SHA)
    def test_repository_write_access_revocation_is_live_and_not_cached(self):
        state=self.accept();self.permission['permission']='read'
        with self.assertRaises(ValueError):risk.live(self.api,state,SHA)
        self.permission.update(permission='write',user=dict(id=99))
        with self.assertRaises(ValueError):self.accept()

    def test_dedicated_one_file_merged_pr_required(self):
        for change in [dict(changed_files=2),dict(merged_at=None),dict(title='ordinary code review')]:
            with self.subTest(change=change),patch.dict(self.pr,change):
                with self.assertRaises(ValueError):self.accept()
        with patch.object(self,'changed_files',[dict(filename='README.md',status='modified')]):
            with self.assertRaises(ValueError):self.accept()
    def test_every_scope_change_requires_new_risk_review(self):
        changes=[lambda:self.case.findings[0].update(version='changed'),
            lambda:self.bundle['normalizedFindings'][0].update(severity='Critical'),
            lambda:self.bundle['native']['securityContext'].update(extra=True),
            lambda:self.bundle['binding']['evidenceFiles'].update(extra='e'*64),
            lambda:next(iter(self.bundle['product']['products'].values())).update(narHash='changed'),
            lambda:self.files['.github/CODEOWNERS'].write_text('* @other\n')]
        for change in changes:
            originals=deepcopy((self.case.findings,self.bundle));owners=self.files['.github/CODEOWNERS'].read_text()
            change()
            with self.assertRaises(ValueError):self.accept()
            self.case.findings,self.bundle=originals;self.files['.github/CODEOWNERS'].write_text(owners)
    def test_expired_future_and_overlong_acceptance_reject(self):
        now=datetime.now(timezone.utc)
        for created,expires in [(now-timedelta(days=2),now-timedelta(days=1)),(now+timedelta(hours=1),now+timedelta(days=1)),(now-timedelta(minutes=1),now+timedelta(days=31))]:
            self.record.update(createdAt=created.isoformat(),expiresAt=expires.isoformat());self.write()
            with self.assertRaises(ValueError):self.accept()
    def test_renewal_cannot_extend_an_old_exact_head_approval(self):
        old=self.path.read_bytes();original=self.api
        self.record['expiresAt']=(datetime.now(timezone.utc)+timedelta(days=2)).isoformat();self.write()
        def api(path):
            if path=='contents/'+risk.PATH+'?ref='+HEAD:return encoded(old)
            return original(path)
        with patch.object(self,'api',side_effect=api):
            with self.assertRaises(ValueError):self.accept()

    def test_missing_unsupported_or_duplicate_record_rejects(self):
        self.path.unlink();self.assertIsNone(self.accept());self.write()
        self.path.write_text('{"kind":"a","kind":"b"}')
        with self.assertRaises(ValueError):self.accept()
        self.write();self.record['acceptedRawFindings'].append('f'*64);self.write()
        with self.assertRaises(ValueError):self.accept()
    def test_partial_acceptance_leaves_blockers_and_technical_failures_are_not_waived(self):
        self.record['acceptedRawFindings']=self.record['acceptedRawFindings'][:1];self.write()
        state=self.accept();self.assertEqual(len(state['raw']),1)
        # Integration: use only this fixture's policy files but execute the real gate.
        with patch.dict(pub.os.environ,dict(self.case.env,MAESTRO_SYSTEM_ROOT=str(self.root))),patch.object(pub,'RISK_POLICY_FILES',tuple(self.files)),patch.object(pub.native,'api',side_effect=self.api):
            # Make the checked policy path identical to the scope's file location.
            (self.root/'.github').mkdir(exist_ok=True);(self.root/'.github/CODEOWNERS').write_text('* @human\n')
            with self.assertRaises(pub.MandatoryVerdictError):pub.consume(self.bundle,self.case.policy_path,'check')
            self.case.case.bundle.joinpath('findings.json').write_text('[]')
            with self.assertRaises(ValueError):pub.consume(self.bundle,self.case.policy_path,'check')
    def test_accepted_gate_permits_high_critical_but_live_revocation_stops_upload(self):
        (self.root/'.github').mkdir(exist_ok=True);self.files['.github/CODEOWNERS']=self.root/'.github/CODEOWNERS';self.files['.github/CODEOWNERS'].write_text('* @human\n')
        scope=pub.native.common.cache_publication.closure(self.bundle['product']);selected=next(iter(scope));calls=[]
        def restore(*args,**kwargs):
            kwargs['closure_metadata'].write_text(json.dumps(scope));self.reviews[0]['state']='DISMISSED'
        with patch.dict(pub.os.environ,dict(self.case.env,MAESTRO_SYSTEM_ROOT=str(self.root))),patch.object(pub,'RISK_POLICY_FILES',tuple(self.files)),patch.object(pub.native,'api',side_effect=self.api):
            result=pub.consume(self.bundle,self.case.policy_path,'check');self.assertEqual(result['status'],'native-policy-clear')
            self.assertEqual(result['verdict']['riskAcceptance']['reviewId'],30)
            with self.assertRaises(ValueError):pub.consume(self.bundle,self.case.policy_path,'publish',transport=Path('/fixture'),
                inspect=lambda *a:dict(status='partial',missing=[selected]),restore=restore,query=lambda paths:scope,
                execute=lambda *a,**kw:calls.append('upload'),probe=lambda *a:dict(status='verified'))
        self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
