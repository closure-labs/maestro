#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit native official refresh keeps receipt, inventory and scanner boundaries."""
import copy
from contextlib import contextmanager,redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=module('official_locator_fixture',Path(__file__).with_name('native-release-target.py'))
refresh=module('official_native_refresh',ROOT/'modules/ci/security/_source/native-refresh.py')
target=fixture.target

class Official(unittest.TestCase):
    def setUp(self):
        self.case=fixture.Target();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.raw=self.case.path.read_bytes();self.commands=[]
        self.target=dict(runId=7,runAttempt=2,revision=fixture.S,mediaProducer=dict(runId=8,runAttempt=1,revision='e'*40),isoSha256='d'*64)
        self.bundle=dict(receipt=dict(runId=7,runAttempt=2,sourceRevision=fixture.S,bootOrigin=self.target['mediaProducer']),result=dict(boot=dict(isoSha256='d'*64)))
    def execute(self,args,**kwargs):
        self.commands.append(args)
        self.assertEqual(args,['gh','api','--method','GET','-H','Accept: application/octet-stream','repos/closure-labs/maestro/releases/assets/9'])
        self.assertTrue(kwargs['check']);self.assertEqual(kwargs['timeout'],90);self.assertIn('preexec_fn',kwargs)
        kwargs['stdout'].write(self.raw)
    def fetch(self,**kwargs):
        return target.fetch('v1.2.3',fixture.M,fixture.P,api=self.case.api,verify=self.case.verify,execute=kwargs.get('execute',self.execute))
    def test_receipt_fetch_is_bounded_read_only_and_never_fetches_payload(self):
        result=self.fetch();self.assertEqual(result['runId'],7);self.assertEqual(len(self.commands),1)
        for field in ('authorization','publicationReady','inventoryVerified','narBytesVerified','isoBytesVerified','findingsAccepted'):self.assertFalse(result[field])
    def test_invalid_descriptor_rejects_before_transfer(self):
        original=copy.deepcopy(self.case.release['assets'][0])
        for change in (dict(size=target.CAP+1),dict(size=0),dict(id=True),dict(digest='bad'),dict(state='new')):
            self.case.release['assets']=[dict(original,**change)]
            with self.subTest(change=change),self.assertRaises(ValueError):self.fetch()
        self.assertEqual(self.commands,[])
    def test_truncated_changed_or_failed_receipt_transfer_never_reaches_verification(self):
        for raw in (self.raw[:-1],b'x'*len(self.raw)):
            self.raw=raw
            with self.assertRaises(ValueError):self.fetch()
        def fail(*args,**kwargs):raise subprocess.CalledProcessError(17,args)
        with self.assertRaises(subprocess.CalledProcessError):self.fetch(execute=fail)
        self.assertIsNone(self.case.command)
    def test_real_subprocess_transfer_preserves_nonzero_and_resource_failure(self):
        root=Path(self.case.temp.name);binary=root/'bin';binary.mkdir();gh=binary/'gh'
        for body in ('raise SystemExit(17)','import sys;sys.stdout.buffer.write(b"x"*(2*1024**2));sys.stdout.buffer.flush()'):
            gh.write_text('#!'+sys.executable+'\n'+body+'\n');gh.chmod(0o700)
            with patch.dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH']),self.assertRaises(subprocess.CalledProcessError):
                self.fetch(execute=target.native.operations.run)
        self.assertIsNone(self.case.command)
    def test_verified_inventory_must_match_shipped_iso_producer_and_media(self):
        refresh.official_binding(self.bundle,self.target)
        for field,value in (('isoSha256','f'*64),('runAttempt',3),('revision','f'*40),('mediaProducer',dict(runId=9,runAttempt=1,revision='e'*40))):
            with self.subTest(field=field),self.assertRaises(ValueError):refresh.official_binding(self.bundle,dict(self.target,**{field:value}))
    def test_official_selector_rejects_unprotected_context_before_reads(self):
        env=dict(GITHUB_REPOSITORY='closure-labs/maestro',GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_SHA=fixture.P)
        for change in (dict(GITHUB_EVENT_NAME='schedule'),dict(GITHUB_REPOSITORY='other/repo'),dict(GITHUB_REF='refs/heads/topic')):
            with patch.dict(os.environ,dict(env,**change)),patch.object(refresh,'module',side_effect=AssertionError('No locator read')),self.assertRaises(ValueError):
                refresh.official_product('v1.2.3',fixture.M,fixture.P)
    def test_main_pipeline_verifies_product_before_single_existing_refresh(self):
        events=[];output=Path(self.case.temp.name)/'health'
        stage=SimpleNamespace(stage_refresh=lambda *a,**k:events.append(('stage',k['discover_origin'])),transport=lambda *a:None)
        distribution=SimpleNamespace(restore=lambda *a:None)
        @contextmanager
        def verified(*args,**kwargs):events.append(('verified',True));yield self.bundle
        def scan(bundle,*args,**kwargs):events.append(('scan',True));return dict(sourceRevision=fixture.S,originalProducer={},producer={})
        original=refresh.module
        def owner(name,path):
            return stage if name=='refresh_stage' else distribution if name=='refresh_distribution' else original(name,path)
        argv=['refresh','--official-tag','v1.2.3','--official-publication-revision',fixture.M,'--policy-revision',fixture.P,'--output',str(output)]
        env=dict(MAESTRO_NATIVE_PREPARE_POLICY=str(ROOT/'modules/ci/authority/_source/decision-policy.json'))
        with patch.dict(os.environ,env),patch.object(sys,'argv',argv),patch.object(refresh,'official_product',return_value=self.target),patch.object(refresh,'module',side_effect=owner),patch.object(refresh.native,'verified_inventory',side_effect=verified),patch.object(refresh,'refresh',side_effect=scan),redirect_stdout(io.StringIO()):
            refresh.main();self.assertEqual(events,[('stage',True),('verified',True),('scan',True)])
            events.clear();self.bundle['result']['boot']['isoSha256']='f'*64
            with self.assertRaises(ValueError):refresh.main()
            self.assertEqual(events,[('stage',True),('verified',True)])
    def test_incomplete_or_conflicting_cli_identities_reject_without_selection(self):
        base=['refresh','--output','unused','--policy-revision',fixture.P]
        for extra in (['--official-tag','v1.2.3'],['--official-publication-revision',fixture.M],['--official-tag','v1.2.3','--official-publication-revision',fixture.M,'--run','7'],['--official-tag','v1.2.3','--official-publication-revision',fixture.M,'--select-current-main']):
            with patch.object(sys,'argv',base+extra),patch.object(refresh,'official_product',side_effect=AssertionError('No selection')),self.assertRaises(ValueError):refresh.main()
    def test_real_shell_wrapper_preserves_explicit_identity_and_rejects_mixed_inputs(self):
        driver=Path(self.case.temp.name)/'args.py';driver.write_text('import sys,json;print(json.dumps(sys.argv[1:]))')
        env=dict(os.environ,MAESTRO_NATIVE_REFRESH_SOURCE=str(driver),NATIVE_OFFICIAL_RELEASE_TAG='v1.2.3',NATIVE_OFFICIAL_PUBLICATION_REVISION=fixture.M,NATIVE_POLICY_REVISION=fixture.P,GITHUB_SHA=fixture.P,NATIVE_REVISION=fixture.P,NATIVE_RUN='',NATIVE_ATTEMPT='',NATIVE_REFRESH_SELECT_CURRENT_MAIN='false')
        source=ROOT/'modules/ci/security/_source/native-refresh.sh'
        r=subprocess.run(['bash',str(source)],env=env,capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr)
        args=json.loads(r.stdout);self.assertIn('--official-tag',args);self.assertNotIn('--run',args);self.assertNotIn('--revision',args)
        env['NATIVE_RUN']='7';r=subprocess.run(['bash',str(source)],env=env,capture_output=True,text=True,timeout=10);self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,'')

if __name__=='__main__':unittest.main()
