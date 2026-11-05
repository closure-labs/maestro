#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native publisher policy is mandatory before any restore, upload or probe."""
from copy import deepcopy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=module('prepare_fixture',Path(__file__).with_name('native-prepare.py'))
pub=module('native_publication',ROOT/'modules/ci/security/_source/native-publication.py')


class Publication(unittest.TestCase):
    def test_real_cli_rejects_partial_refresh_identity_before_any_api_or_transport(self):
        source=ROOT/'modules/ci/security/_source/native-publication.py'
        for extra in (['--health-run','20'],['--health-attempt','1'],['--health-directory','unverified']):
            result=subprocess.run([sys.executable,str(source),'check','--run','7','--attempt','1','--revision','a'*40,*extra],
                capture_output=True,text=True,timeout=10,env=dict(os.environ,GH_TOKEN=''))
            self.assertEqual(result.returncode,2,result.stdout+result.stderr)
            self.assertIn('"error": "ValueError"',result.stderr)

    def setUp(self):
        self.case=fixture.NativePrepare();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.policy=dict(schema_version=2,mode='report',dispositions=[],exceptions=[])
        self.policy_path=self.case.root/'security-policy.json';self.policy_path.write_text(json.dumps(self.policy))
        self.findings=[];self.effective=deepcopy(self.policy);self.app={'dispositions':[]}
        self.case.native['evidence']={}
        self.case.scans['transport']={}
        self.env=dict(os.environ,MAESTRO_NATIVE_PREPARE_POLICY=str(self.case.policy),
            GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',MAESTRO_SYSTEM_ROOT=str(ROOT),GITHUB_REPOSITORY='closure-labs/maestro',GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_SHA=fixture.SHA,
            MAESTRO_NATIVE_PUBLICATION_ENABLED='true',CACHIX_MAESTRO_PUBKEY=pub.KEY,CACHIX_MAESTRO_AUTH_TOKEN='fixture-secret')
        self.review_approved=True
        self.policy_root=self.case.root/'protected-policy'
        self.env['MAESTRO_SYSTEM_ROOT']=str(self.policy_root)
        for name in pub.RISK_POLICY_FILES:
            target=self.policy_root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())

    def finding(self,severity='high',i='a'):
        return dict(advisory='CVE-2026-1234',component='package',version='1',severity=severity,identity=i*64)

    def bundle(self):
        for name,key,value in [('source-policy.json','sourcePolicy',self.policy),('findings.json','findings',self.findings),
             ('effective-policy.json','effectivePolicy',self.effective),('critical-applicability.json','applicability',self.app)]:
            path=self.case.bundle/name;path.write_text(json.dumps(value))
            self.case.native['evidence'][key]=dict(sha256=pub.native.file_hash(path),size=path.stat().st_size)
        self.case.write_bundle()
        bundle=dict(binding=self.case.binding,directory=self.case.bundle,native=self.case.native,product=self.case.product,scans=self.case.scans,
            receipt=dict(sourceRevision=fixture.SHA,runId=7),policyHash=pub.native.common.canonical_hash(self.case.cfg),
            normalizedFindings=[])
        (self.policy_root/pub.POLICY).write_bytes(self.policy_path.read_bytes())
        files={name:self.policy_root/name for name in pub.RISK_POLICY_FILES}
        self.env['NATIVE_FINDINGS_CONTEXT_SHA256']=pub.risk.digest(pub.risk.context(bundle,self.findings,files,'publish',123))
        return bundle

    def api(self,path):
        if path.startswith('releases?per_page=100&page='):return []
        if path.startswith('git/matching-refs/tags/'):return []
        if path.startswith('contents/.github?ref='):return [dict(name='workflows',path='.github/workflows',type='dir',sha='f'*40)]
        if path=='':return dict(id=pub.risk.REPO_ID,full_name='closure-labs/maestro',private=False,visibility='public',default_branch='main')
        if path=='actions/runs/123':return dict(id=123,run_attempt=1,head_sha=fixture.SHA,head_branch='main',
            event='workflow_dispatch',path=pub.risk.WORKFLOWS['publish'],repository=dict(id=pub.risk.REPO_ID),
            status='in_progress',created_at=dt.datetime.now(dt.timezone.utc).isoformat())
        if path=='environments/'+pub.risk.ENVIRONMENT:return dict(id=9,name=pub.risk.ENVIRONMENT,can_admins_bypass=False,
            deployment_branch_policy=dict(protected_branches=True,custom_branch_policies=False),
            protection_rules=[dict(type='required_reviewers',prevent_self_review=False,
                reviewers=[dict(type='User',reviewer=dict(id=pub.risk.REVIEWER_ID))]),dict(type='branch_policy')])
        if path=='actions/runs/123/approvals' and not self.review_approved:return []
        if path=='actions/runs/123/approvals':return [dict(state='approved',environments=[dict(id=9,name=pub.risk.ENVIRONMENT)],user=dict(type='User',id=pub.risk.REVIEWER_ID,login='human'))]
        if path=='collaborators/human/permission':return dict(permission='write',user=dict(id=pub.risk.REVIEWER_ID))
        if path.startswith('contents/') and '?ref=' in path and not path.startswith('contents/'+pub.POLICY+'?ref='):
            import base64
            raw=(self.policy_root/path[len('contents/'):].split('?ref=')[0]).read_bytes()
            return dict(encoding='base64',size=len(raw),content=base64.b64encode(raw).decode())
        if path=='git/ref/heads/main':return {'object':{'sha':fixture.SHA}}
        if path.startswith('contents/'+pub.POLICY+'?ref='):
            import base64
            raw=json.dumps(self.policy).encode();return dict(encoding='base64',size=len(raw),content=base64.b64encode(raw).decode())
        raise AssertionError('Unexpected history/ledger/mutation endpoint '+path)

    def test_release_review_exposes_exact_original_media_and_version_without_authority(self):
        import datetime as dt
        self.findings=[self.finding('critical')];bundle=self.bundle()
        bundle['receipt']['runAttempt']=1
        bundle['receipt']['bootOrigin']=dict(runId=8,runAttempt=2,revision='b'*40)
        artifact=dict(id=50,name='maestro-installer',size_in_bytes=100,digest='sha256:'+'c'*64,
            expired=False,expires_at='2099-01-01T00:00:00Z',workflow_run=dict(id=8,head_sha='b'*40,head_branch='main'))
        calls=[]
        def api(path):
            calls.append(path)
            if path=='actions/runs/123':return dict(self.api(path),path=pub.risk.WORKFLOWS['release'])
            if path.startswith('contents/VERSION?ref='):
                return dict(encoding='base64',size=6,content='My4yLjAK')
            if path.startswith('actions/runs/8/artifacts?'):return dict(artifacts=[artifact])
            return self.api(path)
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=api):
            result=pub.consume(bundle,self.policy_path,'review',review_operation='release')
            self.assertEqual(result['releaseVersion'],'3.2.0');self.assertEqual(result['mediaArtifactId'],50)
            self.assertEqual(result['mediaProducer'],bundle['receipt']['bootOrigin'])
            self.assertFalse(result['authorization']);self.assertFalse(result['publicationReady'])
            self.assertEqual(result['review']['context']['operation'],'release')
            self.assertEqual(result['verdict']['status'],'blocked')
            self.assertFalse(any('/approvals' in path for path in calls))
            for changed in (dict(artifact,expired=True),dict(artifact,size_in_bytes=33*1024**3),dict(artifact,id=True)):
                previous=artifact;artifact=changed
                with self.assertRaises(ValueError):pub.consume(bundle,self.policy_path,'review',review_operation='release')
                artifact=previous

    def test_report_mode_high_critical_unknown_block_before_every_side_effect(self):
        self.review_approved=False
        for severity in ('high','critical','unknown'):
            self.findings=[self.finding(severity)];bundle=self.bundle();calls=[]
            with self.subTest(severity=severity),patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
                with self.assertRaises(ValueError):
                    pub.consume(bundle,self.policy_path,'publish',execute=lambda *a,**k:calls.append('upload'),
                        restore=lambda *a,**k:calls.append('restore'),probe=lambda *a,**k:calls.append('probe'),
                        inspect=lambda *a,**k:calls.append('inspect'))
                self.assertEqual(pub.policy_verdict(bundle,self.policy)['blockingRows'],1);self.assertEqual(calls,[])

    def test_explicit_product_source_and_current_policy_are_distinct(self):
        policy_revision='e'*40;bundle=self.bundle();bundle['receipt']['policyRevision']=policy_revision
        observed=[]
        def api(path):
            observed.append(path)
            if path=='git/ref/heads/main':return {'object':{'sha':policy_revision}}
            self.assertEqual(path,'contents/'+pub.POLICY+'?ref='+policy_revision)
            return self.api(path)
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=api):
            result=pub.consume(bundle,self.policy_path,'check')
        self.assertEqual(bundle['receipt']['sourceRevision'],fixture.SHA)
        self.assertIn('contents/'+pub.POLICY+'?ref='+policy_revision,observed)
        self.assertEqual(result['status'],'native-policy-clear');self.assertFalse(result['authorization'])

    def test_writer_requires_the_current_policy_workflow_context_before_side_effects(self):
        policy_revision='e'*40;bundle=self.bundle();bundle['receipt']['policyRevision']=policy_revision;calls=[]
        def api(path):
            if path=='git/ref/heads/main':return {'object':{'sha':policy_revision}}
            return self.api(path)
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=api):
            with self.assertRaises(ValueError):pub.consume(bundle,self.policy_path,'publish',inspect=lambda *a:calls.append('inspect'))
        self.assertEqual(calls,[])

    def test_malformed_policy_or_partial_health_reject_before_api_or_download(self):
        source=ROOT/'modules/ci/security/_source/native-publication.py'
        for extra in (['--policy-revision','bad'],['--policy-revision','e'*40,'--health-run','20']):
            result=subprocess.run([sys.executable,str(source),'check','--run','7','--attempt','1','--revision',fixture.SHA,*extra],
                capture_output=True,text=True,timeout=10,env=dict(os.environ,GH_TOKEN=''))
            self.assertEqual(result.returncode,2,result.stdout+result.stderr)
            self.assertIn('"error": "ValueError"',result.stderr)

    def test_real_failed_reader_retains_safe_receipt_and_remains_blocked(self):
        (self.case.bin/'gh').write_text('#!'+sys.executable+'\nimport sys\nsys.stderr.write("fixture-sensitive-data (HTTP 403)\\n")\nsys.exit(17)\n')
        output=self.case.root/'failure.json'
        env=dict(os.environ,PATH=str(self.case.bin)+os.pathsep+os.environ['PATH'],
            MAESTRO_NATIVE_PREPARE_POLICY=str(self.case.policy),NATIVE_RESULT_FILE=str(output),
            GH_TOKEN='fixture-sensitive-data')
        result=subprocess.run([sys.executable,str(ROOT/'modules/ci/security/_source/native-publication.py'),
            'review','--review-operation','qualify','--directory',str(self.case.bundle),
            '--run','7','--attempt','1','--revision',fixture.SHA],
            env=env,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2)
        value=json.loads(output.read_text())
        self.assertEqual(value,dict(status='blocked',authorization=False,error='CalledProcessError',
            phase='github-read',githubEndpoint='current-main',exitCode=17,httpStatus=403))
        self.assertNotIn('fixture-sensitive-data',result.stdout+result.stderr+output.read_text())

    def test_low_medium_clear_without_granting_authority(self):
        self.findings=[self.finding('low'),self.finding('medium','b')];bundle=self.bundle()
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
            outcome=pub.consume(bundle,self.policy_path,'check')
        self.assertEqual(outcome['status'],'native-policy-clear');self.assertFalse(outcome['authorization'])
        self.assertFalse(outcome['publicationReady'])

    def test_normalized_related_or_unknown_severity_cannot_be_downgraded(self):
        self.findings=[self.finding('medium')];bundle=self.bundle()
        for severity in ('High','Critical','Unknown'):
            bundle['normalizedFindings']=[{'severity':severity}]
            outcome=pub.policy_verdict(bundle,self.policy)
            self.assertEqual(outcome['status'],'blocked');self.assertEqual(outcome['blockingRows'],0)
            self.assertEqual(outcome['normalizedBlockingIdentities'],1)

    def test_changed_missing_or_unbound_effective_policy_rejects(self):
        bundle=self.bundle();path=self.case.bundle/'findings.json';path.write_text('[] ')
        with self.assertRaises(ValueError):pub.policy_verdict(bundle,self.policy)
        bundle=self.bundle();del bundle['native']['evidence']['findings']
        with self.assertRaises(ValueError):pub.policy_verdict(bundle,self.policy)
        self.effective['exceptions']=[dict(self.finding(),owner='x')];bundle=self.bundle()
        with self.assertRaises(ValueError):pub.policy_verdict(bundle,self.policy)

    def test_invalid_or_expired_exception_does_not_bypass_gate(self):
        row=dict(self.finding(),owner='reviewer',reason='fixture',evidence=['https://example.test/fix'],
            created='2020-01-01',expires='2020-01-02')
        self.policy['exceptions']=[row];self.effective=deepcopy(self.policy);bundle=self.bundle()
        with self.assertRaises(ValueError):pub.policy_verdict(bundle,self.policy)

    def test_native_scope_policy_or_current_main_change_blocks(self):
        bundle=self.bundle()
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',return_value={'object':{'sha':'f'*40}}):
            with self.assertRaises(ValueError):pub.consume(bundle,self.policy_path,'check')
        self.case.policy.write_text(json.dumps(dict(self.case.cfg,maxEvidenceAgeHours=99)))
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
            with self.assertRaises(ValueError):pub.consume(bundle,self.policy_path,'check')

    def test_no_enabled_writer_or_mismatched_cache_key_can_write(self):
        bundle=self.bundle();calls=[]
        with patch.dict(os.environ,dict(self.env,MAESTRO_NATIVE_PUBLICATION_ENABLED='false')),patch.object(pub.native,'api',side_effect=self.api):
            with self.assertRaises(ValueError):pub.consume(bundle,self.policy_path,'publish',execute=lambda *a,**k:calls.append(a))
        self.assertEqual(calls,[])

    def test_clear_publication_uses_signed_scope_and_cold_probe(self):
        bundle=self.bundle();selected=pub.native.common.cache_publication.closure(bundle['product']);path=next(iter(selected));calls=[]
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
            outcome=pub.consume(bundle,self.policy_path,'publish',transport=Path('/fixture'),
                inspect=lambda *a:dict(status='partial',missing=[path]),restore=lambda *a,**k:(calls.append('restore'),k['closure_metadata'].write_text(json.dumps(selected))),
                execute=lambda args,**kwargs:calls.append(args),probe=lambda *a:dict(status='verified',downloadedBytesVerified=True),query=lambda paths:selected)
        self.assertEqual(calls,['restore',['cachix','push','maestro',path]])
        self.assertEqual(outcome['status'],'verified')

    def test_already_verified_cache_still_cold_probes_and_never_restores(self):
        bundle=self.bundle();calls=[]
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
            pub.consume(bundle,self.policy_path,'publish',inspect=lambda *a:dict(status='verified'),
                restore=lambda *a,**k:(calls.append('restore'),k['closure_metadata'].write_text(json.dumps(selected))),execute=lambda *a,**k:calls.append('upload'),
                probe=lambda *a:calls.append('cold') or dict(status='verified'))
        self.assertEqual(calls,['cold'])

    def test_changed_local_reference_graph_blocks_before_upload(self):
        bundle=self.bundle();scope=pub.native.common.cache_publication.closure(bundle['product']);selected=next(iter(scope));calls=[]
        bad=deepcopy(scope);bad[selected]['narHash']='sha256-'+'B'*43+'='
        def restore(*args,**kwargs):kwargs['closure_metadata'].write_text(json.dumps(scope))
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
            with self.assertRaises(ValueError):pub.consume(bundle,self.policy_path,'publish',transport=Path('/fixture'),
                inspect=lambda *a:dict(status='partial',missing=[selected]),restore=restore,query=lambda paths:bad,
                execute=lambda *a,**k:calls.append('upload'),probe=lambda *a:dict(status='verified'))
        self.assertEqual(calls,[])

    def test_real_cli_gate_never_uses_report_mode_as_write_authority(self):
        fake=self.case.bin/'gh';text=fake.read_text()
        marker="    elif path==prefix+'actions/runs/7/attempts/1':value=state['run']"
        inserted="    elif path==prefix+'contents/'+"+repr(pub.POLICY)+"+'?ref='+'a'*40:\n        raw=json.dumps(state['nativeSecurityPolicy']).encode();value={'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}\n"
        text=text.replace(marker,inserted+marker);fake.write_text(text)
        side_effect=self.case.root/'side-effect'
        for binary in ('nix','cachix'):
            path=self.case.bin/binary;path.write_text('#!'+sys.executable+'\nimport os,sys\nfrom pathlib import Path\nPath(os.environ["NATIVE_SIDE_EFFECT_PATH"]).write_text("unexpected")\nsys.exit(99)\n');path.chmod(0o700)
        for severity,expected in [('high',2),('critical',2),('unknown',2),('medium',0),('low',0)]:
            self.findings=[self.finding(severity)];self.bundle()
            self.case.state['nativeSecurityPolicy']=self.policy
            state=self.case.root/'state.json';state.write_text(json.dumps(self.case.state))
            env=dict(self.env,PATH=str(self.case.bin)+os.pathsep+os.environ['PATH'],
                MAESTRO_NATIVE_SECURITY_POLICY=str(self.policy_path),NATIVE_FIXTURE_STATE=str(state),
                NATIVE_FIXTURE_CALLS=str(self.case.calls),NATIVE_FIXTURE_BUNDLE=str(self.case.bundle),
                NATIVE_SIDE_EFFECT_PATH=str(side_effect),PYTHONDONTWRITEBYTECODE='1')
            operation='publish' if expected else 'check'
            result=subprocess.run([sys.executable,str(ROOT/'modules/ci/security/_source/native-publication.py'),operation,
                '--directory',str(self.case.bundle),'--run','7','--attempt','1','--revision',fixture.SHA],
                capture_output=True,text=True,env=env,timeout=20)
            with self.subTest(severity=severity):
                self.assertEqual(result.returncode,expected,result.stdout+result.stderr)
                self.assertFalse(side_effect.exists())
                if expected:self.assertEqual(json.loads(result.stderr)['status'],'blocked')
                else:self.assertFalse(json.loads(result.stdout)['authorization'])

    def test_main_or_expiry_race_after_restore_prevents_upload(self):
        for change in ('main','expiry','policy'):
            bundle=self.bundle();calls=[];changed=[False];selected=next(iter(pub.native.common.cache_publication.closure(bundle['product'])))
            def restore(*args,**kwargs):
                scope=pub.native.common.cache_publication.closure(bundle['product'])
                kwargs['closure_metadata'].write_text(json.dumps(scope))
                changed[0]=True
                if change=='expiry':bundle['scans']['expiresAt']='1970-01-01T00:00:00Z'
                if change=='policy':self.policy_path.write_text('{}')
            def api(path):
                if changed[0] and change=='main' and path=='git/ref/heads/main':return {'object':{'sha':'f'*40}}
                return self.api(path)
            self.policy_path.write_text(json.dumps(self.policy))
            with self.subTest(change=change),patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=api):
                with self.assertRaises(ValueError):pub.consume(bundle,self.policy_path,'publish',transport=Path('/fixture'),
                    inspect=lambda *a:dict(status='partial',missing=[selected]),restore=restore,
                    execute=lambda *a,**k:calls.append('upload'),probe=lambda *a:dict(status='verified'),
                    query=lambda paths:pub.native.common.cache_publication.closure(bundle['product']))
            self.assertEqual(calls,[])
            self.case.scans['expiresAt']=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat()


if __name__=='__main__':unittest.main()
