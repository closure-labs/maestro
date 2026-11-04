#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh-review retry readback; immutable bytes never become approval authority."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('retry_fixture',Path(__file__).with_name('native-release-publish.py'))
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
writer=fixture.writer;pub=fixture.pub;S='a'*40;P='b'*40

class Retry(unittest.TestCase):
    def setUp(self):
        self.case=fixture.ReleasePublish();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.case.receipt['verdict']['riskAcceptance']=dict(runId=123,kind='historical-only')
        self.case.changed();self.old=(self.case.case.output/'native-release-staging.json').read_bytes()
        self.case.env['GITHUB_RUN_ID']='124'
        self.case.receipt['verdict']['riskAcceptance']=dict(runId=124,kind='fresh-current-review')
        self.case.changed();self.signatures=[];self.reads=0
        self.row=dict(id=9,name='native-release-staging.json',state='uploaded',size=len(self.old),digest='sha256:'+hashlib.sha256(self.old).hexdigest())
        self.release=dict(id=3,tag_name='v3.2.0',target_commitish=S,draft=False,assets=[self.row])
        self.original_api=self.case.case.api
        def api(path):
            if path.startswith('releases?per_page=100&page='):return [self.release]
            if path.startswith('git/matching-refs/tags/'):return [dict(ref='refs/tags/v3.2.0',object=dict(type='commit',sha=S))]
            if path.startswith('compare/'):
                sha=path.split('/')[1].split('...')[0];return dict(status='ahead',base_commit=dict(sha=sha),merge_base_commit=dict(sha=sha))
            return self.original_api(path)
        self.case.case.api=api
        def reconcile(repo,product,directory,tag,revision,publish,authorize):
            self.assertEqual((directory/self.row['name']).read_bytes(),self.old)
            self.assertEqual(product['assets'][self.row['name']],self.row['digest'].split(':')[1])
            self.assertEqual(self.case.case.bundle['_riskAcceptance']['context']['runId'],124)
            for phase in ('tag','draft','upload','publish'):authorize();self.case.published.append(phase)
            return dict(status='published',tag=tag)
        self.case.reconcile=reconcile
    def reader(self,native,row):self.reads+=1;self.assertEqual(row,self.row);return self.old
    def verify(self,native,path,revision):self.signatures.append((revision,path.read_bytes()))
    def run_retry(self):return self.case.publish(receipt_reader=self.reader,verify_receipt=self.verify)
    def test_fresh_review_keeps_original_public_receipt_and_payload_binding(self):
        result=self.run_retry();self.assertTrue(result['retainedReceipt']);self.assertEqual(self.reads,1)
        self.assertEqual(len(self.signatures),2)
        self.assertNotEqual(self.signatures[0][1],self.signatures[1][1]);self.assertEqual(self.signatures[1][1],self.old)
        self.assertEqual(self.case.case.bundle['_riskAcceptance']['context']['runId'],124)
        self.assertNotIn('historical-only',json.dumps(self.case.case.bundle['_riskAcceptance']['context']))
    def test_historical_approval_cannot_replace_missing_or_revoked_current_review(self):
        self.case.case.case.review_approved=False
        with self.assertRaises(ValueError):self.run_retry()
        self.assertEqual(self.case.published,[])
        self.case.case.case.review_approved=True
        original=self.case.case.api
        def api(path):
            if path=='collaborators/human/permission':return dict(permission='read',user=dict(id=pub.risk.REVIEWER_ID))
            return original(path)
        self.case.case.api=api
        with self.assertRaises(ValueError):self.run_retry()
        self.assertEqual(self.case.published,[])
    def test_stored_payload_producer_media_or_bytes_change_blocks_all_writes(self):
        base=json.loads(self.old)
        for change in (dict(sourceRun=999),dict(sourceAttempt=True),dict(isoSha256='f'*64),dict(mediaProducer={}),dict(assets={})):
            self.old=json.dumps(dict(base,**change),sort_keys=True).encode();self.row.update(size=len(self.old),digest='sha256:'+hashlib.sha256(self.old).hexdigest())
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_retry()
        self.assertEqual(self.case.published,[])
    def test_original_signer_is_authenticated_without_replaying_old_review(self):
        old=json.loads(self.old);old['policyRevision']=P;self.old=json.dumps(old).encode()
        self.row.update(size=len(self.old),digest='sha256:'+hashlib.sha256(self.old).hexdigest())
        self.assertTrue(self.run_retry()['retainedReceipt']);self.assertEqual([s[0] for s in self.signatures],[S,P])
        self.assertEqual(self.case.case.bundle['_riskAcceptance']['context']['policyRevision'],S)
    def test_retry_under_fresh_policy_keeps_old_provenance_but_requires_current_review(self):
        self.case.env['GITHUB_SHA']=P;self.case.case.bundle['receipt']['policyRevision']=P
        self.case.receipt['policyRevision']=P;self.case.changed()
        original=self.case.case.api
        def api(path):
            value=original(path)
            if path=='git/ref/heads/main':return dict(object=dict(sha=P))
            if path=='actions/runs/123':return dict(value,head_sha=P)
            return value
        self.case.case.api=api
        self.assertTrue(self.run_retry()['retainedReceipt'])
        self.assertEqual([s[0] for s in self.signatures],[P,S])
        self.assertEqual(self.case.case.bundle['_riskAcceptance']['context']['policyRevision'],P)
    def test_access_loss_after_readback_still_blocks_before_reconciliation(self):
        def verify(native,path,revision):
            self.verify(native,path,revision)
            if len(self.signatures)==2:self.case.case.revoked=True
        with self.assertRaises(ValueError):self.case.publish(receipt_reader=self.reader,verify_receipt=verify)
        self.assertEqual(self.case.published,[])
    def test_unrelated_original_signer_rejects_without_writes(self):
        old=json.loads(self.old);old['policyRevision']=P;self.old=json.dumps(old).encode()
        self.row.update(size=len(self.old),digest='sha256:'+hashlib.sha256(self.old).hexdigest())
        original=self.case.case.api
        def api(path):return dict(status='diverged',base_commit=dict(sha=P),merge_base_commit=dict(sha='f'*40)) if path.startswith('compare/') else original(path)
        self.case.case.api=api
        with self.assertRaises(ValueError):self.run_retry()
        self.assertEqual(self.case.published,[])

    def test_signature_or_read_failure_never_becomes_absence_or_overwrite(self):
        def failed(*args):raise subprocess.CalledProcessError(17,args)
        with self.assertRaises(subprocess.CalledProcessError):self.case.publish(receipt_reader=failed,verify_receipt=self.verify)
        self.assertEqual(self.case.published,[])
        calls=0
        def verify(*args):
            nonlocal calls
            calls+=1
            if calls==2:raise ValueError('Stored signature forged')
        with self.assertRaises(ValueError):self.case.publish(receipt_reader=self.reader,verify_receipt=verify)
        self.assertEqual(self.case.published,[])
    def test_duplicate_stored_receipt_or_wrong_release_rejects(self):
        self.release['assets']=[self.row,self.row]
        with self.assertRaises(ValueError):self.run_retry()
        self.assertEqual(self.case.published,[])
        self.release['assets']=[self.row];self.release['target_commitish']='e'*40
        with self.assertRaises(ValueError):self.run_retry()
        self.assertEqual(self.case.published,[])
    def test_actual_reconciler_keeps_noop_and_rejects_late_remote_receipt_change(self):
        spec=importlib.util.spec_from_file_location('retry_assets',ROOT/'modules/release/publication/_source/publication-assets.py')
        assets=importlib.util.module_from_spec(spec);spec.loader.exec_module(assets)
        changed=False;mutations=[]
        def reconcile(repo,product,directory,tag,revision,publish,authorize):
            records={name:dict(id=i+30,name=name,state='uploaded',size=(directory/name).stat().st_size) for i,name in enumerate(product['assets'])}
            def github(endpoint,method='GET',payload=None):
                if method!='GET':mutations.append(method);raise AssertionError('No write on an existing immutable release')
                if endpoint.endswith('/git/ref/tags/'+tag):return dict(ref='refs/tags/'+tag,object=dict(type='commit',sha=revision))
                if '/assets?' in endpoint:return list(records.values())
                if endpoint.endswith('/releases/3'):return self.release
                if '/releases?' in endpoint:return [self.release]
                raise AssertionError(endpoint)
            def digest(repository,asset):return '0'*64 if changed and asset['name']==self.row['name'] else product['assets'][asset['name']]
            return assets.reconcile(repo,product,directory,tag,revision,publish,authorize,github=github,download=digest,
                send=lambda *a:(_ for _ in ()).throw(AssertionError('No duplicate upload')))
        self.case.reconcile=reconcile
        self.assertEqual(self.run_retry()['status'],'published')
        self.assertEqual(mutations,[])
        changed=True
        with self.assertRaises(ValueError):self.run_retry()
        self.assertEqual(mutations,[])

    def test_partial_draft_resumes_missing_payloads_without_reuploading_receipt(self):
        spec=importlib.util.spec_from_file_location('retry_partial_assets',ROOT/'modules/release/publication/_source/publication-assets.py')
        assets=importlib.util.module_from_spec(spec);spec.loader.exec_module(assets)
        self.release['draft']=True;writes=[]
        def reconcile(repo,product,directory,tag,revision,publish,authorize):
            remote={self.row['name']:dict(self.row)}
            def github(endpoint,method='GET',payload=None):
                if method=='PATCH':
                    self.assertEqual(payload,{'draft':False});writes.append('publish');self.release['draft']=False;return self.release
                self.assertEqual(method,'GET')
                if endpoint.endswith('/git/ref/tags/'+tag):return dict(ref='refs/tags/'+tag,object=dict(type='commit',sha=revision))
                if '/assets?' in endpoint:return list(remote.values())
                if endpoint.endswith('/releases/3'):return self.release
                if '/releases?' in endpoint:return [self.release]
                raise AssertionError(endpoint)
            def upload(repository,tag,paths):
                for path in paths:
                    self.assertNotEqual(path.name,self.row['name']);writes.append(path.name)
                    remote[path.name]=dict(id=30+len(remote),name=path.name,state='uploaded',size=path.stat().st_size)
            result=assets.reconcile(repo,product,directory,tag,revision,publish,authorize,github=github,
                download=lambda repository,asset:product['assets'][asset['name']],send=upload)
            self.assertEqual(product['assets'][self.row['name']],self.row['digest'].split(':')[1])
            return result
        self.case.reconcile=reconcile
        result=self.run_retry();self.assertTrue(result['retainedReceipt']);self.assertEqual(result['status'],'published')
        self.assertNotIn(self.row['name'],writes);self.assertEqual(writes[-1],'publish')
        self.assertEqual(set(writes[:-1]),set(self.case.receipt['assets']))

    def test_real_receipt_transport_is_read_only_bounded_and_preserves_failure(self):
        root=self.case.case.root;binary=root/'transport-bin';binary.mkdir();gh=binary/'gh'
        code='''import sys,os
assert sys.argv[1:]==['api','--method','GET','-H','Accept: application/octet-stream','repos/closure-labs/maestro/releases/assets/9']
assert not any('credential' in x for x in sys.argv)
mode=os.environ.get('RECEIPT_FIXTURE_MODE','valid')
if mode=='failed':raise SystemExit(17)
if mode=='large':sys.stdout.buffer.write(b'x'*(2*1024**2));sys.stdout.buffer.flush()
else:sys.stdout.buffer.write(open(os.environ['RECEIPT_FIXTURE_FILE'],'rb').read())
'''
        gh.write_text('#!'+sys.executable+'\n'+code);gh.chmod(0o700)
        stored=root/'stored';stored.write_bytes(self.old)
        with patch.dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],RECEIPT_FIXTURE_FILE=str(stored)):
            self.assertEqual(writer.read_receipt(pub.native,self.row),self.old)
            for mode in ('failed','large'):
                with patch.dict(os.environ,RECEIPT_FIXTURE_MODE=mode),self.assertRaises(subprocess.CalledProcessError):writer.read_receipt(pub.native,self.row)
            with self.assertRaises(ValueError):writer.read_receipt(pub.native,dict(self.row,digest='sha256:'+'0'*64))
    def test_new_destination_workflow_limit_and_existing_noop_are_distinct(self):
        def api(path):
            if path=='':return dict(id=1127149753,full_name=pub.native.REPO,default_branch='main')
            if path.startswith('releases?'):return []
            if path.startswith('git/matching-refs/'):return []
            if path.startswith('contents/.github?ref='):return [dict(name='workflows',path='.github/workflows',type='dir',sha=('d' if path.endswith(S) else 'e')*40)]
            raise AssertionError(path)
        with patch.object(pub.native,'api',side_effect=api),self.assertRaises(writer.ReleaseWorkflowPermissionError):writer.destination(pub.native,'v3.2.0',S,P)
        existing=lambda path: [self.release] if path.startswith('releases?') else [dict(ref='refs/tags/v3.2.0',object=dict(type='commit',sha=S))]
        with patch.object(pub.native,'api',side_effect=existing):self.assertEqual(writer.destination(pub.native,'v3.2.0',S,P)['release']['id'],3)
        def readonly(path):return [] if path.startswith('releases?') else [dict(ref='refs/tags/v3.2.0',object=dict(type='commit',sha=S))]
        with patch.object(pub.native,'api',side_effect=readonly):self.assertTrue(writer.destination(pub.native,'v3.2.0',S,P,read_only=True)['requiresWritableReadback'])
    def test_destination_transport_and_malformed_metadata_never_mean_absence(self):
        def failed(path):raise subprocess.CalledProcessError(17,['gh','api'])
        with patch.object(pub.native,'api',side_effect=failed),self.assertRaises(subprocess.CalledProcessError):writer.destination(pub.native,'v3.2.0',S,P)
        for bad in (None,{},[{'tag_name':'v3.2.0','id':True}]):
            with patch.object(pub.native,'api',return_value=bad),self.assertRaises(ValueError):writer.destination(pub.native,'v3.2.0',S,P)
        def missing(path):
            if path.startswith('releases?') or path.startswith('git/matching-refs/'):return []
            if path=='':return dict(id=1127149753,full_name=pub.native.REPO,default_branch='main')
            return [dict(name='workflows',path='.github/workflows',type='symlink',sha='f'*40)]
        with patch.object(pub.native,'api',side_effect=missing),self.assertRaises(ValueError):writer.destination(pub.native,'v3.2.0',S,P)

    def test_same_workflow_git_tree_allows_older_source_without_extra_permission(self):
        calls=[]
        def api(path):
            calls.append(path)
            if path=='':return dict(id=1127149753,full_name=pub.native.REPO,default_branch='main')
            if path.startswith('releases?') or path.startswith('git/matching-refs/'):return []
            return [dict(name='workflows',path='.github/workflows',type='dir',sha='f'*40)]
        with patch.object(pub.native,'api',side_effect=api):self.assertIsNone(writer.destination(pub.native,'v3.2.0',S,P)['release'])
        self.assertEqual(sum(p.startswith('contents/') for p in calls),2)

if __name__=='__main__':unittest.main()
