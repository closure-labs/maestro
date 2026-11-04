#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive refresh retains one original closure and independently fresh health."""
from copy import deepcopy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


fixture=module('input_fixture',Path(__file__).with_name('native-refresh-inputs.py'))
refresh=module('refresh_producer',fixture.ROOT/'modules/ci/security/_source/native-refresh.py')


class NativeRefresh(unittest.TestCase):
    def setUp(self):
        self.inputs=fixture.RefreshInputs();self.inputs.setUp();self.addCleanup(self.inputs.doCleanups)
        self.case=self.inputs.case
        self.case.scans['transport']={'parts':['original-closure.part']}
        self.case.write_bundle()
        self.output=self.case.root/'fresh';self.calls=[];self.change=None;self.mainReads=0;self.policy_revision='a'*40
        self.env=dict(GITHUB_REPOSITORY=refresh.native.REPO,GITHUB_REF='refs/heads/main',
            GITHUB_SHA='a'*40,GITHUB_RUN_ID='20',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='workflow_dispatch')
        self.bundle=dict(inventoryOnly=True,directory=self.case.bundle,receipt=dict(sourceRevision='a'*40,runId=7,runAttempt=1),
            native=self.case.native,scans=dict(self.case.scans,transport={'parts':['original-closure.part']}),
            policyHash=refresh.native.common.canonical_hash(self.case.cfg),
            inputIdentities={name:refresh.native.file_hash(self.case.bundle/name) for name in refresh.INPUTS})

    def test_current_scanner_policy_does_not_reissue_the_original_product(self):
        self.policy_revision='e'*40;self.bundle['receipt']['policyRevision']=self.policy_revision
        self.env['GITHUB_SHA']=self.policy_revision
        result=self.run_refresh()
        self.assertEqual(result['schemaVersion'],2)
        self.assertEqual(result['policyRevision'],self.policy_revision)
        self.assertEqual(result['producer']['revision'],self.policy_revision)
        self.assertEqual(result['sourceRevision'],'a'*40)
        self.assertEqual(result['originalProducer']['revision'],'a'*40)
        self.assertFalse(result['authorization']);self.assertFalse(result['publicationReady'])
        self.assertEqual(self.calls.count('scan'),1)
        self.assertFalse((self.output/'maestro-system.spdx.json').exists())
        self.assertFalse((self.output/'product.json').exists())

    def api(self, path):
        self.assertEqual(path,'git/ref/heads/main');self.mainReads+=1
        return {'object':{'sha':'f'*40 if self.change=='main' and self.mainReads>=3 else self.policy_revision}}

    def scan(self, env):
        self.calls.append('scan')
        self.assertEqual(env['SECURITY_INVENTORY'],str(self.case.bundle))
        fresh=deepcopy(self.case.native);now=dt.datetime.now(dt.timezone.utc)
        fresh['scannedAt']=now.isoformat();fresh['database']['built']=now.isoformat()
        if self.change=='stale':fresh['scannedAt']=(now-dt.timedelta(minutes=2)).isoformat();fresh['database']['built']=fresh['scannedAt']
        if self.change=='database':fresh['database']['valid']=False
        if self.change=='context':fresh['securityContext']['tcpPorts']=[1234]
        if self.change=='subjects':fresh['subjects'][0]['narHash']='sha256-'+'B'*43+'='
        hashes=self.output/'inputs.sha256';hashes.write_text((self.case.bundle/'inputs.sha256').read_text())
        if self.change=='inputs':hashes.write_text(hashes.read_text().replace('original','changed').replace('a','b',1))
        if self.change=='original':(self.case.bundle/'ci-result.json').write_text('{}')
        fresh['evidence']['inputHashes']=dict(sha256=refresh.native.file_hash(hashes),size=hashes.stat().st_size)
        for name,key,value in [('findings.json','findings',[]),('source-policy.json','sourcePolicy',{}),
                ('effective-policy.json','effectivePolicy',{}),('critical-applicability.json','applicability',{})]:
            path=self.output/name;path.write_text(json.dumps(value))
            fresh['evidence'][key]=dict(sha256=refresh.native.file_hash(path),size=path.stat().st_size)
        (self.output/'security-result.json').write_text(json.dumps(fresh))
        if self.change=='extra':(self.output/'original-closure.part').write_text('unexpected transport copy')
        if self.change=='missing':(self.output/'findings.json').unlink()

    def run_refresh(self, scan=None, scheduled=False):
        def download():self.calls.append('download');return self.case.root/'original-transport'
        def restore(path, manifest, roots):
            self.calls.append('restore');self.assertEqual(manifest,self.bundle['scans']['transport'])
            self.assertEqual(len(roots),len(self.case.subjects))
        def query(paths):
            self.calls.append('query');return {p: ('changed' if self.change=='nar' else h) for p,h in paths.items()}
        with patch.dict(os.environ,self.env):
            return refresh.refresh(self.bundle,self.output,self.case.cfg,download,restore,query,scan or self.scan,self.api,scheduled=scheduled)

    def test_scheduled_refresh_requires_both_explicit_route_and_enabled_policy(self):
        self.env['GITHUB_EVENT_NAME']='schedule'
        with self.assertRaises(ValueError):self.run_refresh(scheduled=True)
        self.assertEqual(self.calls,[])
        self.env['MAESTRO_NATIVE_REFRESH_ENABLED']='true'
        with self.assertRaises(ValueError):self.run_refresh()
        self.assertEqual(self.calls,[])
        self.run_refresh(scheduled=True)
        self.assertEqual(self.calls,['download','restore','query','scan'])

    def test_one_original_restore_one_scan_no_reexport_or_inventory_copy(self):
        result=self.run_refresh()
        self.assertEqual(self.calls,['download','restore','query','scan'])
        self.assertEqual({p.name for p in self.output.iterdir()},{'security-result.json','inputs.sha256','native-health.json',*refresh.native.PUBLICATION_FILES})
        self.assertFalse(result['authorization']);self.assertFalse(result['publicationReady'])
        self.assertEqual(result['originalProducer']['runId'],7);self.assertEqual(result['producer']['runId'],20)
        self.assertEqual(result['originalProof']['scans.json']['sha256'],refresh.native.file_hash(self.case.bundle/'scans.json'))
        self.assertEqual(result['originalTransport'],self.bundle['scans']['transport'])

    def test_changed_health_context_inputs_or_live_main_reject_and_clean_output(self):
        for change in ('stale','database','context','subjects','inputs','main','original','extra','missing'):
            self.change=change;self.calls=[];self.mainReads=0
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_refresh()
            self.assertFalse(self.output.exists())
            self.case.write_bundle()

    def test_nar_failure_blocks_scan(self):
        self.change='nar'
        with self.assertRaises(ValueError):self.run_refresh()
        self.assertEqual(self.calls,['download','restore','query']);self.assertFalse(self.output.exists())

    def test_real_scanner_process_failure_propagates_and_removes_partial_output(self):
        def fail(env):
            (self.output/'partial').write_text('incomplete')
            refresh.native.operations.run([sys.executable,'-c','raise SystemExit(17)'],check=True,timeout=5)
        with self.assertRaises(subprocess.CalledProcessError) as error:self.run_refresh(fail)
        self.assertEqual(error.exception.returncode,17);self.assertFalse(self.output.exists())

    def test_wrong_source_purpose_or_missing_transport_never_downloads(self):
        self.bundle['inventoryOnly']=False
        with self.assertRaises(ValueError):self.run_refresh()
        self.assertEqual(self.calls,[])
        self.bundle['inventoryOnly']=True;self.bundle['scans'].pop('transport')
        with self.assertRaises(ValueError):self.run_refresh()
        self.assertEqual(self.calls,[])

    def test_only_explicit_protected_manual_source_can_refresh(self):
        for key,value in [('GITHUB_EVENT_NAME','schedule'),('GITHUB_EVENT_NAME','workflow_run'),
                          ('GITHUB_EVENT_NAME','pull_request'),('GITHUB_REF','refs/heads/topic'),
                          ('GITHUB_REPOSITORY','attacker/maestro'),('GITHUB_SHA','f'*40)]:
            with self.subTest(key=key,value=value),patch.dict(self.env,{key:value}),self.assertRaises(ValueError):self.run_refresh()
            self.assertEqual(self.calls,[])

    def test_retained_boot_links_both_original_executed_proof_files(self):
        self.bundle['receipt']['bootOrigin']=dict(runId=6,runAttempt=1)
        for name in ('original-ci-result.json','original-boot.log'):(self.case.bundle/name).write_text('authenticated original fixture')
        result=self.run_refresh()
        for name in ('original-ci-result.json','original-boot.log'):
            self.assertEqual(result['originalProof'][name]['sha256'],refresh.native.file_hash(self.case.bundle/name))

    def test_changed_scope_policy_and_output_resource_overflow_reject(self):
        self.bundle['policyHash']='changed'
        with self.assertRaises(ValueError):self.run_refresh()
        self.assertEqual(self.calls,[])
        self.bundle['policyHash']=refresh.native.common.canonical_hash(self.case.cfg)
        with patch.object(refresh.native,'MAX_DOCUMENT',8),self.assertRaises(ValueError):self.run_refresh()
        self.assertFalse(self.output.exists())

    def test_real_scan_timeout_propagates_and_cleans_output(self):
        def timeout(env):
            refresh.native.operations.run([sys.executable,'-c','while True: pass'],check=True,timeout=0.05)
        with self.assertRaises(subprocess.TimeoutExpired):self.run_refresh(timeout)
        self.assertFalse(self.output.exists())

    def test_default_scanner_keeps_temporary_database_contract_separate_from_report_bounds(self):
        def execute(args,**kwargs):
            self.assertEqual(args,['maestro-ci-security-scan']);self.assertEqual(kwargs['timeout'],3600)
            self.assertTrue(kwargs['check']);self.assertNotIn('preexec_fn',kwargs)
            self.scan(kwargs['env'])
        with patch.dict(os.environ,self.env),patch.object(refresh.native.operations,'run',side_effect=execute):
            result=refresh.refresh(self.bundle,self.output,self.case.cfg,lambda:self.case.root/'transport',
                lambda *args:None,lambda paths:dict(paths),api=self.api)
        self.assertFalse(result['authorization'])


class MainSelection(unittest.TestCase):
    def setUp(self):
        self.sha='a'*40;self.run=dict(id=7,run_attempt=2,workflow_id=30,path=refresh.native.WORKFLOW,
            head_sha=self.sha,head_branch='main',event='push',status='completed',conclusion='success',
            repository=dict(id=1127149753,full_name=refresh.native.REPO),head_repository=dict(id=1127149753,full_name=refresh.native.REPO))
        self.rows=[self.run];self.changed=False;self.paths=[]
        self.env=dict(GITHUB_REPOSITORY=refresh.native.REPO,GITHUB_REF='refs/heads/main',GITHUB_SHA=self.sha,
            GITHUB_EVENT_NAME='schedule',MAESTRO_NATIVE_REFRESH_ENABLED='true')
    def api(self,path):
        self.paths.append(path)
        if path=='branches/main':return dict(protected=True,commit=dict(sha=self.sha))
        if path=='actions/workflows/ci.yml':return dict(id=30,path=refresh.native.WORKFLOW,state='active')
        if path.startswith('actions/workflows/ci.yml/runs?'):return dict(total_count=len(self.rows),workflow_runs=self.rows)
        if path=='actions/runs/7/attempts/2':return self.run
        if path=='git/ref/heads/main':return dict(object=dict(sha='b'*40 if self.changed else self.sha))
        raise AssertionError('Unexpected non-selection endpoint '+path)
    def select(self):
        with patch.dict(os.environ,self.env),patch.object(refresh.native,'api',side_effect=self.api):
            return refresh.select_current_main(self.api)
    def test_exact_current_main_producer_needs_no_ledger_or_latest_choice(self):
        self.assertEqual(self.select(),(7,2,self.sha))
        self.assertFalse(any('decisions' in p or 'artifacts' in p for p in self.paths))
    def test_missing_ambiguous_old_or_untrusted_producer_does_not_fall_back(self):
        original=self.run.copy()
        for rows in ([],[None],[original,original], [dict(original,head_sha='b'*40)],
                     [dict(original,event='pull_request')],[dict(original,workflow_id=31)],
                     [dict(original,conclusion='failure')],[dict(original,run_attempt=True)],
                     [dict(original,head_repository=dict(id=3,full_name=refresh.native.REPO))]):
            with self.subTest(rows=rows):
                self.rows=rows
                with self.assertRaises(ValueError):self.select()
    def test_real_wrapper_keeps_automatic_and_explicit_identities_separate(self):
        import tempfile,subprocess,sys,json
        with tempfile.TemporaryDirectory() as temp:
            script=Path(temp)/'arguments.py';script.write_text('import sys,json; print(json.dumps(sys.argv[1:]))')
            env=dict(os.environ,**self.env,NATIVE_REFRESH_SELECT_CURRENT_MAIN='true',NATIVE_POLICY_REVISION=self.sha,
                NATIVE_RUN='',NATIVE_ATTEMPT='',NATIVE_REVISION=self.sha,MAESTRO_NATIVE_REFRESH_SOURCE=str(script))
            args=['bash',str(fixture.ROOT/'modules/ci/security/_source/native-refresh.sh')]
            result=subprocess.run(args,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            values=json.loads(result.stdout);self.assertIn('--select-current-main',values);self.assertNotIn('--run',values)
            for changed in (dict(NATIVE_RUN='7'),dict(NATIVE_REVISION='b'*40)):
                result=subprocess.run(args,env=dict(env,**changed),capture_output=True,text=True,timeout=10)
                self.assertNotEqual(result.returncode,0)

    def test_disabled_policy_unprotected_context_and_main_race_reject(self):
        for key,value in [('MAESTRO_NATIVE_REFRESH_ENABLED','false'),('GITHUB_REF','refs/pull/1/merge'),
                          ('GITHUB_EVENT_NAME','pull_request'),('GITHUB_SHA','bad')]:
            previous=self.env[key];self.env[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.select()
            self.env[key]=previous
        self.changed=True
        with self.assertRaises(ValueError):self.select()


if __name__=='__main__':unittest.main()
