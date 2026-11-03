#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh health must authenticate original and new producers independently."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import importlib.util
import base64
import datetime as dt
import os
import subprocess
import sys
import resource


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


fixture=module('refresh_fixture',Path(__file__).with_name('native-refresh.py'))
health=module('native_health',fixture.fixture.ROOT/'modules/ci/security/_source/native-health.py')


class NativeHealth(unittest.TestCase):
    def setUp(self):
        self.case=fixture.NativeRefresh();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.main='a'*40;self.runPatch={};self.forged=False;self.calls=[]
        self.policy=dict(schema_version=2,mode='report',dispositions=[],exceptions=[])
        self.fresh_findings=[]
        self.create_report()

    def create_report(self):
        def scan(env):
            self.case.scan(env);report=self.case.output/'security-result.json';fresh=json.loads(report.read_text())
            for name,key in [('findings.json','findings'),('source-policy.json','sourcePolicy'),
                ('effective-policy.json','effectivePolicy'),('critical-applicability.json','applicability')]:
                value=self.fresh_findings if name=='findings.json' else {'dispositions':[]} if name=='critical-applicability.json' else self.policy
                path=self.case.output/name;path.write_text(json.dumps(value))
                fresh['evidence'][key]=dict(sha256=health.native.file_hash(path),size=path.stat().st_size)
            report.write_text(json.dumps(fresh))
        self.case.run_refresh(scan)

    def api(self,path):
        self.calls.append(path)
        if path=='git/ref/heads/main':return {'object':{'sha':self.main}}
        self.assertEqual(path,'actions/runs/20/attempts/1')
        return dict(dict(id=20,run_attempt=1,head_sha='a'*40,head_branch='main',
            repository={'full_name':health.native.REPO},head_repository={'full_name':health.native.REPO},
            path=health.WORKFLOW,event='workflow_dispatch',status='completed',conclusion='success'),**self.runPatch)

    def attestation(self,*args):
        self.assertEqual(args[:2],('attestation','verify'))
        for flag,expected in [('--repo',health.native.REPO),('--signer-workflow',health.native.REPO+'/'+health.WORKFLOW),
            ('--source-ref','refs/heads/main'),('--source-digest','a'*40),('--signer-digest','a'*40),('--format','json')]:
            self.assertEqual(args[args.index(flag)+1],expected)
        self.assertIn('--deny-self-hosted-runners',args)
        return [{'verificationResult':{'statement':{'subject':[{'digest':{'sha256':'f'*64 if self.forged else health.native.file_hash(Path(args[2]))}}]}}}]

    def verify(self):
        with patch.object(health.native,'api',side_effect=self.api),patch.object(health.native,'response',side_effect=self.attestation):
            with health.verified(self.case.bundle,self.case.output,20,1,self.case.case.cfg) as bundle:return bundle.copy()

    def test_both_proofs_bound_without_reissuing_original_scan_or_copying_inventory(self):
        bundle=self.verify()
        self.assertFalse(bundle['inventoryOnly']);self.assertEqual(bundle['directory'],self.case.case.bundle)
        self.assertEqual(bundle['scans'],self.case.bundle['scans'])
        self.assertEqual(bundle['receipt'],self.case.bundle['receipt'])
        self.assertEqual(bundle['healthManifest']['producer']['runId'],20)
        self.assertNotEqual(bundle['native']['scannedAt'],self.case.bundle['native']['scannedAt'])
        self.assertEqual(self.calls,['git/ref/heads/main','actions/runs/20/attempts/1','git/ref/heads/main','git/ref/heads/main'])
        self.assertFalse(bundle['policyDirectory'].exists()) # Scoped frozen data, no persistent authority.

    def test_wrong_health_signer_subject_and_changed_main_reject(self):
        self.forged=True
        with self.assertRaises(ValueError):self.verify()
        self.forged=False;self.main='f'*40
        with self.assertRaises(ValueError):self.verify()

    def test_failed_fork_wrong_attempt_or_workflow_producer_rejects(self):
        for patch_value in ({'conclusion':'failure'},{'run_attempt':2},{'path':'.github/workflows/ci.yml'},
                            {'head_sha':'b'*40},{'head_repository':{'full_name':'attacker/maestro'}},
                            {'event':'schedule'},{'event':'workflow_run'},{'event':'pull_request'}):
            self.runPatch=patch_value
            with self.subTest(patch_value=patch_value),self.assertRaises(ValueError):self.verify()

    def test_changed_original_proof_or_fresh_raw_finding_bytes_reject(self):
        path=self.case.case.bundle/'ci-result.json';old=path.read_bytes();path.write_bytes(b'{}')
        with self.assertRaises(ValueError):self.verify()
        path.write_bytes(old);(self.case.output/'findings.json').write_text('[{}]')
        with self.assertRaises(ValueError):self.verify()

    def test_expired_substituted_or_overlong_manifest_rejects(self):
        path=self.case.output/'native-health.json';old=json.loads(path.read_text())
        for key,value in [('expiresAt','2000-01-01T00:00:00Z'),('expiresAt','2099-01-01T00:00:00Z'),
                          ('originalProducer',{'runId':8}),('originalTransport',{}),('authorization',True)]:
            path.write_text(json.dumps(dict(old,**{key:value})))
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.verify()

    def test_aggregate_resource_bound_and_symlink_reject(self):
        with patch.object(health.native,'MAX_BUNDLE',1),self.assertRaises(ValueError):self.verify()
        path=self.case.output/'findings.json';path.unlink();path.symlink_to(self.case.output/'source-policy.json')
        with self.assertRaises(OSError):self.verify()

    def test_expired_original_identity_plus_fresh_health_still_requires_mandatory_risk_gate(self):
        import shutil
        pub=module('health_publication',fixture.fixture.ROOT/'modules/ci/security/_source/native-publication.py')
        policy_path=self.case.case.root/'security-policy.json';policy_path.write_text(json.dumps(self.policy))
        old=dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=3)
        self.case.case.native['scannedAt']=old.isoformat();self.case.case.native['database']['built']=old.isoformat()
        self.case.case.scans['expiresAt']=(old+dt.timedelta(hours=24)).isoformat();self.case.case.write_bundle()
        self.case.bundle['scans']['expiresAt']=self.case.case.scans['expiresAt']
        def api(path):
            if path=='git/ref/heads/main':return {'object':{'sha':'a'*40}}
            self.assertEqual(path,'contents/'+pub.POLICY+'?ref='+'a'*40)
            raw=policy_path.read_bytes();return dict(encoding='base64',size=len(raw),content=base64.b64encode(raw).decode())
        for severity in (None,'high','critical','unknown'):
            shutil.rmtree(self.case.output)
            self.fresh_findings=[] if severity is None else [dict(advisory='CVE-2026-1',component='package',version='1',severity=severity,identity='a'*64)]
            self.create_report()
            with patch.object(health.native,'api',side_effect=self.api),patch.object(health.native,'response',side_effect=self.attestation):
                with health.verified(self.case.bundle,self.case.output,20,1,self.case.case.cfg) as bundle:
                    with patch.object(pub.native,'api',side_effect=api),patch.dict(os.environ,MAESTRO_NATIVE_PREPARE_POLICY=str(self.case.case.policy)):
                        if severity is None:self.assertEqual(pub.consume(bundle,policy_path,'check')['status'],'native-policy-clear')
                        else:
                            with self.assertRaises(pub.MandatoryVerdictError):pub.consume(bundle,policy_path,'check')

    def test_real_cli_verifies_both_producers_and_never_writes_for_unaccepted_blockers(self):
        self.exercise_cli((None,'high','critical','unknown'))

    def test_generated_large_original_and_fresh_reports_fit_bounded_real_cli(self):
        self.case.case.native['diagnostics']=['x'*4096]*13600
        self.case.case.write_bundle()
        self.exercise_cli((None,))
        self.assertGreater((self.case.case.bundle/'scans.json').stat().st_size,55_706_156)
        self.assertGreater((self.case.output/'security-result.json').stat().st_size,52_521_292)
        print(json.dumps(dict(generatedRefreshReportFixture=True,
            maxParentRssKiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            maxChildRssKiB=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,liveRefresh=False)))

    def exercise_cli(self,severities):
        import shutil
        pub=module('cli_health_publication',fixture.fixture.ROOT/'modules/ci/security/_source/native-publication.py')
        c=self.case.case;fake=c.bin/'gh';text=fake.read_text()
        marker="    elif path==prefix+'actions/runs/7/attempts/1':value=state['run']"
        inserted="    elif path==prefix+'actions/runs/20/attempts/1':value=state['healthRun']\n"
        inserted+="    elif path==prefix+'contents/'+"+repr(pub.POLICY)+"+'?ref='+'a'*40:\n        raw=json.dumps(state['nativeSecurityPolicy']).encode();value={'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}\n"
        text=text.replace(marker,inserted+marker).replace("('--signer-workflow','closure-labs/maestro/.github/workflows/ci.yml')",
            "('--signer-workflow','closure-labs/maestro/.github/workflows/security.yml' if Path(args[2]).name=='native-health.json' else 'closure-labs/maestro/.github/workflows/ci.yml')")
        fake.write_text(text)
        c.state['healthRun']=dict(id=20,run_attempt=1,head_sha='a'*40,head_branch='main',
            repository={'full_name':health.native.REPO},head_repository={'full_name':health.native.REPO},
            path=health.WORKFLOW,event='workflow_dispatch',status='completed',conclusion='success')
        c.state['nativeSecurityPolicy']=self.policy
        state=c.root/'state.json';state.write_text(json.dumps(c.state))
        policy=c.root/'security-policy.json';policy.write_text(json.dumps(self.policy))
        marker=c.root/'unexpected-write'
        for name in ('nix','cachix'):
            binary=c.bin/name;binary.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text("unexpected")\nraise SystemExit(99)\n');binary.chmod(0o700)
        env=dict(os.environ,PATH=str(c.bin)+os.pathsep+os.environ['PATH'],MAESTRO_NATIVE_PREPARE_POLICY=str(c.policy),
            MAESTRO_NATIVE_SECURITY_POLICY=str(policy),NATIVE_FIXTURE_STATE=str(state),NATIVE_FIXTURE_CALLS=str(c.calls),
            NATIVE_FIXTURE_BUNDLE=str(c.bundle),PYTHONDONTWRITEBYTECODE='1',MAESTRO_NATIVE_PUBLICATION_ENABLED='true',
            CACHIX_MAESTRO_PUBKEY=pub.KEY,CACHIX_MAESTRO_AUTH_TOKEN='fixture-only',**self.case.env)
        for severity in severities:
            shutil.rmtree(self.case.output)
            self.fresh_findings=[] if severity is None else [dict(advisory='CVE-2026-1',component='package',version='1',severity=severity,identity='a'*64)]
            self.create_report()
            result=subprocess.run([sys.executable,str(fixture.fixture.ROOT/'modules/ci/security/_source/native-publication.py'),
                'check' if severity is None else 'publish','--directory',str(c.bundle),'--run','7','--attempt','1','--revision','a'*40,
                '--health-directory',str(self.case.output),'--health-run','20','--health-attempt','1'],
                env=env,capture_output=True,text=True,timeout=20)
            with self.subTest(severity=severity):
                self.assertEqual(result.returncode,0 if severity is None else 2,result.stdout+result.stderr)
                self.assertFalse(marker.exists())
                if severity is None:self.assertFalse(json.loads(result.stdout)['authorization'])
                else:self.assertEqual(json.loads(result.stderr)['verdict']['blockingRows'],1)


if __name__=='__main__':unittest.main()
