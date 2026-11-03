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
            GITHUB_REPOSITORY='closure-labs/maestro',GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_SHA=fixture.SHA,
            MAESTRO_NATIVE_PUBLICATION_ENABLED='true',CACHIX_MAESTRO_PUBKEY=pub.KEY,CACHIX_MAESTRO_AUTH_TOKEN='fixture-secret')

    def finding(self,severity='high',i='a'):
        return dict(advisory='CVE-2026-1234',component='package',version='1',severity=severity,identity=i*64)

    def bundle(self):
        for name,key,value in [('source-policy.json','sourcePolicy',self.policy),('findings.json','findings',self.findings),
             ('effective-policy.json','effectivePolicy',self.effective),('critical-applicability.json','applicability',self.app)]:
            path=self.case.bundle/name;path.write_text(json.dumps(value))
            self.case.native['evidence'][key]=dict(sha256=pub.native.file_hash(path),size=path.stat().st_size)
        self.case.write_bundle()
        return dict(directory=self.case.bundle,native=self.case.native,product=self.case.product,scans=self.case.scans,
            receipt=dict(sourceRevision=fixture.SHA,runId=7),policyHash=pub.native.common.canonical_hash(self.case.cfg),
            normalizedFindings=[])

    def api(self,path):
        if path=='git/ref/heads/main':return {'object':{'sha':fixture.SHA}}
        if path.startswith('contents/'+pub.POLICY+'?ref='):
            import base64
            raw=json.dumps(self.policy).encode();return dict(encoding='base64',size=len(raw),content=base64.b64encode(raw).decode())
        raise AssertionError('Unexpected history/ledger/mutation endpoint '+path)

    def test_report_mode_high_critical_unknown_block_before_every_side_effect(self):
        for severity in ('high','critical','unknown'):
            self.findings=[self.finding(severity)];bundle=self.bundle();calls=[]
            with self.subTest(severity=severity),patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
                with self.assertRaises(pub.MandatoryVerdictError) as error:
                    pub.consume(bundle,self.policy_path,'publish',execute=lambda *a,**k:calls.append('upload'),
                        restore=lambda *a,**k:calls.append('restore'),probe=lambda *a,**k:calls.append('probe'),
                        inspect=lambda *a,**k:calls.append('inspect'))
                self.assertEqual(error.exception.outcome['blockingRows'],1);self.assertEqual(calls,[])

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
                if expected:self.assertEqual(json.loads(result.stderr)['verdict']['blockingRows'],1)
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
