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
        self.case=self.inputs.case;self.case.write_bundle()
        self.output=self.case.root/'fresh';self.calls=[];self.change=None;self.mainReads=0
        self.env=dict(GITHUB_REPOSITORY=refresh.native.REPO,GITHUB_REF='refs/heads/main',
            GITHUB_SHA='a'*40,GITHUB_RUN_ID='20',GITHUB_RUN_ATTEMPT='1')
        self.bundle=dict(inventoryOnly=True,directory=self.case.bundle,receipt=dict(sourceRevision='a'*40,runId=7,runAttempt=1),
            native=self.case.native,scans=dict(self.case.scans,transport={'parts':['original-closure.part']}),
            policyHash=refresh.native.common.canonical_hash(self.case.cfg),
            inputIdentities={name:refresh.native.file_hash(self.case.bundle/name) for name in refresh.INPUTS})

    def api(self, path):
        self.assertEqual(path,'git/ref/heads/main');self.mainReads+=1
        return {'object':{'sha':'f'*40 if self.change=='main' and self.mainReads>=3 else 'a'*40}}

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
        (self.output/'security-result.json').write_text(json.dumps(fresh))

    def run_refresh(self, scan=None):
        def download():self.calls.append('download');return self.case.root/'original-transport'
        def restore(path, manifest, roots):
            self.calls.append('restore');self.assertEqual(manifest,self.bundle['scans']['transport'])
            self.assertEqual(len(roots),len(self.case.subjects))
        def query(paths):
            self.calls.append('query');return {p: ('changed' if self.change=='nar' else h) for p,h in paths.items()}
        with patch.dict(os.environ,self.env):
            return refresh.refresh(self.bundle,self.output,self.case.cfg,download,restore,query,scan or self.scan,self.api)

    def test_one_original_restore_one_scan_no_reexport_or_inventory_copy(self):
        result=self.run_refresh()
        self.assertEqual(self.calls,['download','restore','query','scan'])
        self.assertEqual({p.name for p in self.output.iterdir()},{'security-result.json','inputs.sha256','native-health.json'})
        self.assertFalse(result['authorization']);self.assertFalse(result['publicationReady'])
        self.assertEqual(result['originalProducer']['runId'],7);self.assertEqual(result['producer']['runId'],20)
        self.assertEqual(result['originalProof']['scans.json']['sha256'],refresh.native.file_hash(self.case.bundle/'scans.json'))
        self.assertEqual(result['originalTransport'],self.bundle['scans']['transport'])

    def test_changed_health_context_inputs_or_live_main_reject_and_clean_output(self):
        for change in ('stale','database','context','subjects','inputs','main','original'):
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


if __name__=='__main__':unittest.main()
