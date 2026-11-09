#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tiny public-byte fixtures: no network, Nix evaluation or real ISO."""
import copy
from contextlib import contextmanager
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('probe', ROOT/'modules/ci/security/_source/native-public-probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
P = 'a'*40

class Probe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.original = self.root/'original'; self.original.mkdir()
        self.payload = self.root/'public'; self.payload.mkdir(); self.base = 'maestro-v1.2.3'; self.iso = b'tiny verified ISO'
        self.data = {self.base+'.iso.part-01': self.iso[:5], self.base+'.iso.part-02': self.iso[5:]}
        self.sha = lambda data: hashlib.sha256(data).hexdigest()
        self.data[self.base+'.iso.sha256'] = (self.sha(self.iso)+'  '+self.base+'.iso\n').encode()
        self.spdx = {'spdxVersion':'SPDX-2.3'}
        for kind in ('spdx','cdx'):
            raw = json.dumps(self.spdx if kind=='spdx' else {'bomFormat':'CycloneDX'}).encode()
            (self.original/('maestro-system.'+kind+'.json')).write_bytes(raw)
            name = self.base+'.'+kind+'.json.gz'; self.data[name] = gzip.compress(raw)
            self.data[name+'.sha256'] = (self.sha(self.data[name])+'  '+name+'\n').encode()
        self.target = dict(tag='v1.2.3', releaseId=4, publicationRevision=P, isoSha256=self.sha(self.iso),
            assets={n:dict(size=len(b),sha256=self.sha(b)) for n,b in self.data.items()})
        self.remote = [dict(id=i+1,name=n,size=len(b),digest='sha256:'+self.sha(b),state='uploaded') for i,(n,b) in enumerate(self.data.items())]
        self.remote.append(dict(id=99,name='native-release-staging.json'))
        self.commands = []; self.proofs = []; self.forge = False
    def api(self,path):
        self.assertEqual(path,'releases/tags/v1.2.3'); return dict(id=4,assets=copy.deepcopy(self.remote))
    def execute(self,args,**kwargs):
        self.commands.append(args); self.assertEqual(args[:5],['gh','api','--method','GET','-H'])
        row = next(r for r in self.remote if str(r['id'])==args[-1].split('/')[-1])
        self.assertTrue(kwargs['check']); self.assertEqual(kwargs['timeout'],600); self.assertIn('preexec_fn',kwargs)
        kwargs['stdout'].write(self.data[row['name']])
    def verify(self,*args):
        self.proofs.append(args); predicate=args[args.index('--predicate-type')+1]
        self.assertEqual(args[args.index('--source-digest')+1],P)
        self.assertEqual(args[args.index('--signer-digest')+1],P)
        self.assertIn('--deny-self-hosted-runners',args)
        return [dict(verificationResult=dict(statement=dict(predicateType=predicate,
            subject=[dict(name=self.base+'.iso',digest=dict(sha256='f'*64 if self.forge else self.sha(self.iso)))],predicate=self.spdx)))]
    def run_assets(self):
        return probe.assets(dict(directory=self.original),self.target,self.payload,api=self.api,
            transfer=lambda row,path:probe.download(row,path,execute=self.execute),verify=self.verify)
    def test_complete_public_bytes_and_both_attestations(self):
        result=self.run_assets(); self.assertTrue(all(result.values())); self.assertEqual(len(self.proofs),2)
        self.assertEqual(len(self.commands),len(self.data)); self.assertFalse((self.payload/(self.base+'.iso')).exists())
    def test_missing_part_and_changed_descriptor_fail_before_download(self):
        for kind in ('part','descriptor','extra','receipt'):
            with self.subTest(kind=kind):
                target=copy.deepcopy(self.target); remote=copy.deepcopy(self.remote)
                if kind=='part': del self.target['assets'][self.base+'.iso.part-01']
                elif kind=='extra': self.target['assets']['extra']=dict(size=1,sha256='f'*64)
                elif kind=='receipt': self.remote[-1]['name']='other.json'
                else: self.remote[0]['digest']='sha256:'+'f'*64
                with self.assertRaises(ValueError): self.run_assets()
                self.target=target; self.remote=remote
        self.assertEqual(self.commands,[])
    def test_corrupt_download_fails_before_attestations(self):
        name=self.base+'.iso.part-01'; self.data[name]=b'wrong'
        with self.assertRaises(ValueError): self.run_assets()
        self.assertEqual(self.proofs,[])
    def test_final_name_forgery_rejected(self):
        self.forge=True
        with self.assertRaises(ValueError): self.run_assets()
    def test_public_sbom_must_equal_original_inventory(self):
        (self.original/'maestro-system.cdx.json').write_bytes(b'wrong')
        with self.assertRaises(ValueError): self.run_assets()
        self.assertEqual(self.proofs,[])
    def test_download_error_propagates(self):
        def fail(*args,**kwargs): raise subprocess.CalledProcessError(7,args)
        with self.assertRaises(subprocess.CalledProcessError): probe.download(self.remote[0],self.payload/'one',execute=fail)
    def test_selection_requires_protected_context(self):
        env=dict(GITHUB_REPOSITORY=probe.native.REPO,GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='schedule')
        for change in (dict(GITHUB_REPOSITORY='other/repo'),dict(GITHUB_REF='refs/heads/topic'),dict(GITHUB_EVENT_NAME='push')):
            with patch.dict(os.environ,dict(env,**change)),self.assertRaises(ValueError):
                probe.select(P,api=lambda _:self.fail('No reads before protected context'))
    def test_selection_reauthenticates_signed_release_not_metadata(self):
        env=dict(GITHUB_REPOSITORY=probe.native.REPO,GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='schedule')
        with patch.dict(os.environ,env),patch.object(probe.locator,'fetch',return_value=self.target) as fetch:
            self.assertEqual(probe.select(P,api=lambda _:dict(id=4,tag_name='v1.2.3',draft=False,prerelease=False)),self.target)
            fetch.assert_called_once_with('v1.2.3',None,P,discover_signer=True)
            with self.assertRaises(ValueError): probe.select(P,api=lambda _:dict(id=5,tag_name='v1.2.3',draft=False,prerelease=False))
    def test_post_transfer_reauthenticates_full_receipt(self):
        with patch.object(probe.refresh,'official_current') as current,patch.object(probe.locator,'fetch',return_value=dict(self.target,receiptSha256='changed')):
            with self.assertRaises(ValueError): probe.current(self.target,P)
            current.assert_called_once()
    def test_disk_headroom_checked_before_transfer(self):
        with patch.object(probe.shutil,'disk_usage',return_value=SimpleNamespace(free=0)),self.assertRaises(ValueError): self.run_assets()
        self.assertEqual(self.commands,[])
    def test_total_size_bounded_before_transfer(self):
        self.target['assets'][self.base+'.iso.part-01']['size']=probe.MAX_ISO+1
        with self.assertRaises(ValueError): self.run_assets()
        self.assertEqual(self.commands,[])
    def test_run_keeps_integrity_separate_from_risk_and_health(self):
        target=dict(self.target,runId=7,runAttempt=1,revision=P)
        bundle=dict(product={},directory=self.original)
        @contextmanager
        def inventory(*args,**kwargs): yield bundle
        loader=SimpleNamespace(stage_refresh=lambda *a,**k:P)
        reader=SimpleNamespace(probe=lambda *a:dict(downloadedBytesVerified=True,signaturesVerified=True))
        with patch.dict(os.environ,dict(GITHUB_SHA=P,MAESTRO_NATIVE_PREPARE_POLICY='policy.json')), \
             patch.object(probe,'select',return_value=target),patch.object(probe,'module',side_effect=[loader,reader]), \
             patch.object(probe.native,'verified_inventory',side_effect=inventory),patch.object(probe.refresh,'official_binding'), \
             patch.object(probe,'assets',return_value=dict(isoBytesVerified=True)),patch.object(probe,'current') as current, \
             patch.object(probe.publication,'emit') as emit:
            probe.run(); current.assert_called_once_with(target,P)
            result=emit.call_args.args[0]
            for key in ('authorization','publicationReady','findingsAccepted','currentHealthVerified'): self.assertIs(result[key],False)
            self.assertTrue(result['narBytesVerified']); self.assertTrue(result['inventoryVerified'])
    def test_total_budget_wraps_run(self):
        with patch.object(probe.native.operations,'budget') as budget,patch.object(probe,'run') as run:
            probe.main(); budget.assert_called_once_with(3000); run.assert_called_once()

if __name__=='__main__': unittest.main()
