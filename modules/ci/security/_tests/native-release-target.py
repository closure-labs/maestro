#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded official-release identity preparation; no live calls or writers."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('target',ROOT/'modules/ci/security/_source/native-release-target.py')
target=importlib.util.module_from_spec(spec);spec.loader.exec_module(target)
S='a'*40;M='b'*40;P='c'*40

class Target(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/target.NAME;self.calls=[];self.command=None;self.main_reads=0;self.tag_reads=0
        self.receipt=dict(schemaVersion=1,status='staged-native-release-assets',authorization=False,publicationReady=False,
            sourceRevision=S,sourceRun=7,sourceAttempt=2,policyRevision=M,tag='v1.2.3',version='1.2.3',
            isoBytesVerified=True,narBytesVerified=False,isoSha256='d'*64,
            mediaProducer=dict(runId=8,runAttempt=1,revision='e'*40),verdict={'riskAcceptance':'not trusted by locator'})
        self.release=dict(id=3,tag_name='v1.2.3',draft=False,prerelease=False,assets=[])
        self.write();self.change_main=False;self.change_tag=False;self.proof='valid';self.relation=True
    def write(self,raw=None):
        raw=raw or json.dumps(self.receipt).encode();self.path.write_bytes(raw)
        self.release['assets']=[dict(id=9,name=target.NAME,state='uploaded',size=len(raw),digest='sha256:'+hashlib.sha256(raw).hexdigest())]
    def api(self,p):
        self.calls.append(p)
        if p=='git/ref/heads/main':
            self.main_reads+=1;return {'object':{'sha':'f'*40 if self.change_main and self.main_reads>1 else P}}
        if p=='releases/tags/v1.2.3':return copy.deepcopy(self.release)
        if p=='git/ref/tags/v1.2.3':
            self.tag_reads+=1;return {'object':{'type':'commit','sha':'f'*40 if self.change_tag and self.tag_reads>1 else S}}
        if p.startswith('compare/'):
            rev=p.split('/')[1].split('...')[0];return dict(status='ahead' if self.relation else 'diverged',base_commit={'sha':rev},merge_base_commit={'sha':rev})
        raise AssertionError(p)
    def verify(self,*args):
        self.command=args
        if self.proof=='failure':raise subprocess.CalledProcessError(1,args)
        if self.proof=='none':return []
        return [{'verificationResult':{'statement':dict(predicateType='https://slsa.dev/provenance/v1',subject=[dict(name=target.NAME,digest={'sha256':'0'*64 if self.proof=='forged' else target.native.file_hash(Path(args[2]))})])}}]
    def run_target(self,**kwargs):
        return target.resolve(self.path,'v1.2.3',M,P,api=self.api,verify=self.verify,**kwargs)
    def test_valid_receipt_only_locates_original_product_never_accepts_risk(self):
        result=self.run_target();self.assertEqual((result['runId'],result['runAttempt'],result['revision']),(7,2,S))
        for name in ('authorization','publicationReady','inventoryVerified','narBytesVerified','isoBytesVerified','findingsAccepted'):self.assertIs(result[name],False)
        self.assertEqual(self.command.count('--source-digest'),1);self.assertEqual(self.command[self.command.index('--source-digest')+1],M)
        self.assertIn(target.native.REPO+'/.github/workflows/release.yml',self.command)
        self.assertIn('--deny-self-hosted-runners',self.command)
        self.assertTrue(all(p.startswith(('git/','releases/tags/','compare/')) for p in self.calls))
    def test_missing_forged_or_failed_signature_rejects(self):
        for proof in ('none','forged','failure'):
            self.proof=proof
            with self.subTest(proof=proof),self.assertRaises((ValueError,subprocess.CalledProcessError)):self.run_target()
    def test_changed_product_signer_tag_version_or_authority_rejects(self):
        changes=[dict(sourceRevision='f'*40),dict(policyRevision='f'*40),dict(tag='v9.0.0'),dict(version='9.0.0'),dict(authorization=True),dict(publicationReady=True),dict(isoBytesVerified=False),dict(narBytesVerified=True),dict(schemaVersion=True)]
        original=copy.deepcopy(self.receipt)
        for change in changes:
            self.receipt=dict(original,**change);self.write()
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_target()
    def test_missing_invalid_or_boolean_producer_identity_rejects(self):
        original=copy.deepcopy(self.receipt)
        for change in (dict(sourceRun=True),dict(sourceAttempt=0),dict(mediaProducer={}),dict(mediaProducer=dict(runId=8,runAttempt=True,revision=S)),dict(isoSha256='bad')):
            self.receipt=dict(original,**change);self.write()
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_target()
    def test_draft_prerelease_or_wrong_release_rejects(self):
        for change in (dict(draft=True),dict(prerelease=True),dict(tag_name='v8.0.0'),dict(id=True)):
            self.release.update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_target()
            self.release.update(id=3,tag_name='v1.2.3',draft=False,prerelease=False)
    def test_missing_duplicate_or_changed_public_receipt_rejects(self):
        original=copy.deepcopy(self.release['assets'])
        for assets in ([],original*2,[dict(original[0],digest='sha256:'+'0'*64)],[dict(original[0],size=1)],[dict(original[0],state='new')]):
            self.release['assets']=assets
            with self.subTest(assets=assets),self.assertRaises(ValueError):self.run_target()
    def test_main_and_tag_races_reject(self):
        self.change_main=True
        with self.assertRaises(ValueError):self.run_target()
        self.main_reads=0;self.tag_reads=0;self.change_main=False;self.change_tag=True
        with self.assertRaises(ValueError):self.run_target()
    def test_diverged_product_or_signer_rejects(self):
        self.relation=False
        with self.assertRaises(ValueError):self.run_target()
    def test_duplicate_json_symlink_and_oversized_receipts_reject(self):
        self.write(b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaises(ValueError):self.run_target()
        self.write(b' '* (target.CAP+1))
        with self.assertRaises(ValueError):self.run_target()
        self.path.unlink();self.path.symlink_to('/dev/null')
        with self.assertRaises(OSError):self.run_target()
    def test_workflows_do_not_execute_private_locator_directly(self):
        for folder in ('.github/workflows',):
            for path in (ROOT/folder).rglob('*'):
                if path.is_file():self.assertNotIn('native-release-target',path.read_text())

if __name__=='__main__':unittest.main()
