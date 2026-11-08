#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded staged-byte checks and native release authorization boundaries."""
import gzip
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=module('native_release_stage_fixture',Path(__file__).with_name('native-release-stage.py'))
writer=module('native_release_writer',ROOT/'modules/release/publication/_source/native-release-publish.py')
pub=fixture.pub

class ReleasePublish(unittest.TestCase):
    def setUp(self):
        self.case=fixture.ReleaseStage();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.final=self.case.root/'maestro-v3.2.0.iso';self.receipt=self.case.stage(final_iso=self.final)
        self.env=dict(self.case.env,MAESTRO_NATIVE_RELEASE_ENABLED='true')
        self.calls=[];self.published=[]
    def attest(self,args,**kwargs):
        self.assertEqual(args,['maestro-ci-release-attestations']);self.assertTrue(kwargs['check'])
        self.assertEqual(kwargs['env']['SOURCE_SHA'],self.case.bundle['receipt'].get('policyRevision',self.case.bundle['receipt']['sourceRevision']))
        self.assertEqual(kwargs['env']['RELEASE_TAG'],'v3.2.0')
        root=Path(kwargs['cwd']);self.assertEqual((Path(kwargs['env']['RUNNER_TEMP'])/self.final.name).read_bytes(),self.final.read_bytes())
        self.assertEqual((root/'candidate/maestro-system.spdx.json').read_bytes(),(self.case.bundle['directory']/'maestro-system.spdx.json').read_bytes())
        self.calls.append('provenance-and-spdx')
    def reconcile(self,repo,product,directory,tag,revision,publish,authorize):
        self.calls.append('reconcile');self.assertTrue(publish)
        self.assertEqual(set(product['assets']),set(self.receipt['assets'])|{'native-release-staging.json'})
        self.assertEqual((directory/'native-release-staging.json').read_bytes(),(self.case.output/'native-release-staging.json').read_bytes())
        self.assertEqual(product['revision'],self.case.bundle['receipt']['sourceRevision'])
        for name,digest in product['assets'].items():self.assertEqual(pub.native.file_hash(directory/name),digest)
        for phase in ('tag','draft','upload','publish'):
            authorize();self.published.append(phase)
        return dict(status='published',tag=tag,revision=revision)
    def publish(self,**kwargs):
        original=self.case.api
        def api(path):
            identity=int(self.env.get('GITHUB_RUN_ID','123'))
            mapped=path.replace('actions/runs/'+str(identity),'actions/runs/123')
            value=original(mapped)
            if path=='actions/runs/'+str(identity):value=dict(value,id=identity,path=pub.risk.WORKFLOWS['release'])
            return value
        files={'VERSION':self.case.root/'risk-version'};files['VERSION'].write_text('3.2.0\n')
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=api):
            state=pub.risk.plan(self.case.bundle,[],files,api,'release')
            os.environ['NATIVE_FINDINGS_CONTEXT_SHA256']=state['contextSha256']
            state['rebuild']=lambda:pub.risk.context(self.case.bundle,[],files,'release',int(self.env.get('GITHUB_RUN_ID','123')))
            self.case.bundle['_riskAcceptance']=state
            return writer.publish(self.case.bundle,self.case.output,self.final,self.case.case.policy_path,
                publication=pub,assets=SimpleNamespace(reconcile=self.reconcile),execute=kwargs.pop('execute',self.attest),verify_receipt=kwargs.pop('verify_receipt',self.verify_receipt),**kwargs)
    def verify_receipt(self,native,path,revision):
        self.assertEqual(path.name,'native-release-staging.json')
        self.assertEqual(path.read_bytes(),(self.case.output/path.name).read_bytes())
        self.assertEqual(revision,self.case.bundle['receipt'].get('policyRevision',self.case.bundle['receipt']['sourceRevision']))

    def changed(self):
        (self.case.output/'native-release-staging.json').write_text(json.dumps(self.receipt))
    def test_direct_release_writer_cannot_bypass_the_findings_gate(self):
        with patch.dict(os.environ,self.env),self.assertRaises(ValueError):
            writer.publish(self.case.bundle,self.case.output,self.final,self.case.case.policy_path,
                publication=pub,assets=SimpleNamespace(reconcile=self.reconcile),execute=self.attest)
        self.assertEqual(self.published,[]);self.assertEqual(self.calls,[])

    def test_qualification_receipt_rejected_even_with_fresh_production_review(self):
        self.receipt.update(status='nonpublishing-release-qualification-assets',findingsAccepted=False)
        self.changed()
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.calls,[]);self.assertEqual(self.published,[])

    def test_direct_writer_rejects_qualification_context(self):
        self.case.bundle['_riskAcceptance']={'context':{'operation':'release-qualify'}}
        with patch.dict(os.environ,self.env),self.assertRaises(ValueError):
            writer.publish(self.case.bundle,self.case.output,self.final,self.case.case.policy_path,
                publication=pub,assets=SimpleNamespace(reconcile=self.reconcile),execute=self.attest)
        self.assertEqual(self.calls,[]);self.assertEqual(self.published,[])

    def test_exact_staged_bytes_final_provenance_and_each_live_write_boundary(self):
        result=self.publish();self.assertEqual(self.calls,['provenance-and-spdx','reconcile'])
        self.assertEqual(self.published,['tag','draft','upload','publish'])
        self.assertEqual(result['status'],'published');self.assertFalse(result['authorization'])
        self.assertTrue(result['isoBytesVerified']);self.assertFalse(result['narBytesVerified'])
        self.assertFalse(list(self.case.root.glob('.native-release-writer-*')))
    def test_verification_needs_no_cross_filesystem_iso_or_document_hardlinks(self):
        with patch.object(writer.os,'link',side_effect=AssertionError('No cross-filesystem link permitted')):
            self.assertEqual(self.publish()['status'],'published')

    def test_disabled_or_wrong_repository_event_source_rejects_without_public_operations(self):
        for key,value in [('MAESTRO_NATIVE_RELEASE_ENABLED','false'),('GITHUB_REPOSITORY','other/repo'),('GITHUB_EVENT_NAME','push'),('GITHUB_SHA','f'*40)]:
            with self.subTest(key=key),patch.dict(self.env,{key:value}),self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.calls,[]);self.assertEqual(self.published,[])
    def test_inventory_only_cannot_publish(self):
        self.case.bundle['inventoryOnly']=True
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.calls,[])
    def test_mismatched_staging_producer_revision_and_version_reject(self):
        for key,value in [('sourceRun',999),('sourceAttempt',2),('sourceAttempt',True),('sourceRevision','f'*40),('policyRevision','e'*40),('version','9.9.9'),('authorization',True),('narBytesVerified',True),('mediaProducer',{}),('mediaProducer',dict(runId=True,runAttempt=1,revision='a'*40))]:
            previous=self.receipt.get(key)
            with self.subTest(key=key):
                self.receipt[key]=value;self.changed()
                with self.assertRaises(ValueError):self.publish()
                if previous is None:self.receipt.pop(key)
                else:self.receipt[key]=previous
                self.changed()
        self.assertEqual(self.calls,[])
    def test_missing_extra_nonregular_and_changed_asset_reject(self):
        path=self.case.output/'unexpected';path.write_text('extra')
        with self.assertRaises(ValueError):self.publish()
        path.unlink();name=next(iter(self.receipt['assets']));path=self.case.output/name;raw=path.read_bytes();path.unlink()
        with self.assertRaises(ValueError):self.publish()
        path.symlink_to(self.final)
        with self.assertRaises(ValueError):self.publish()
        path.unlink();path.write_bytes(b'x'*len(raw))
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.published,[])
    def test_authenticated_iso_and_sbom_override_forged_staging_receipt(self):
        name='maestro-v3.2.0.iso.part-01';path=self.case.output/name;raw=path.read_bytes();path.write_bytes(b'x'*len(raw))
        self.receipt['assets'][name]['sha256']=pub.native.file_hash(path);self.changed()
        with self.assertRaises(ValueError):self.publish()
        path.write_bytes(raw);self.receipt['assets'][name]['sha256']=pub.native.file_hash(path)
        name='maestro-v3.2.0.spdx.json.gz';path=self.case.output/name;path.write_bytes(gzip.compress(b'forged inventory'))
        self.receipt['assets'][name]=dict(size=path.stat().st_size,sha256=pub.native.file_hash(path))
        checksum=self.case.output/(name+'.sha256');checksum.write_text(pub.native.file_hash(path)+'  '+name+'\n')
        self.receipt['assets'][checksum.name]=dict(size=checksum.stat().st_size,sha256=pub.native.file_hash(checksum));self.changed()
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.published,[])
    def test_checksum_and_descriptor_resource_bounds_reject_before_attestation(self):
        name=self.final.name+'.sha256';path=self.case.output/name
        path.write_bytes(b'x'*513);self.receipt['assets'][name]=dict(size=513,sha256=pub.native.file_hash(path));self.changed()
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.calls,[])
        manifest=self.case.output/'native-release-staging.json';manifest.write_bytes(b' '* (1024**2+1))
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.calls,[])

    def test_final_name_attestation_failure_propagates_without_upload(self):
        def failed(*a,**k):raise subprocess.CalledProcessError(3,a)
        with self.assertRaises(subprocess.CalledProcessError):self.publish(execute=failed)
        self.assertEqual(self.published,[]);self.assertFalse(list(self.case.root.glob('.native-release-writer-*')))
    def test_main_drift_before_upload_or_publication_stops_next_mutation(self):
        original=self.case.api;counter=0
        def api(path):
            nonlocal counter
            if path=='git/ref/heads/main':
                counter+=1
                if counter>=4:return dict(object=dict(sha='f'*40))
            return original(path)
        with patch.object(self.case,'api',side_effect=api),self.assertRaises(ValueError):self.publish()
        self.assertLessEqual(len(self.published),1);self.assertNotIn('upload',self.published)
    def test_bounded_disk_rejection_and_mutation_failure_cleanup(self):
        with patch.object(writer.shutil,'disk_usage',return_value=SimpleNamespace(free=0)),self.assertRaises(ValueError):self.publish()
        def failed(*args):raise ValueError('upload denied')
        with patch.object(self,'reconcile',side_effect=failed),self.assertRaises(ValueError):self.publish()
        self.assertFalse(list(self.case.root.glob('.native-release-writer-*')))
    def test_missing_or_invalid_receipt_attestation_blocks_all_mutations(self):
        for proof in ([],[{'verificationResult':{'statement':{'predicateType':'https://slsa.dev/provenance/v1',
                'subject':[{'name':'native-release-staging.json','digest':{'sha256':'0'*64}}]}}}]):
            with self.subTest(proof=proof),patch.object(pub.native,'response',return_value=proof),self.assertRaises(ValueError):
                self.publish(verify_receipt=None)
        self.assertEqual(self.calls,[]);self.assertEqual(self.published,[])

    def test_receipt_verifier_pins_policy_signer_and_exact_predicate_and_name(self):
        path=self.case.output/'native-release-staging.json';revision='b'*40
        good={'predicateType':'https://slsa.dev/provenance/v1','subject':[{'name':path.name,'digest':{'sha256':pub.native.file_hash(path)}}]}
        def response(*args):
            self.assertEqual(args[args.index('--source-digest')+1],revision)
            self.assertEqual(args[args.index('--signer-digest')+1],revision)
            self.assertEqual(args[args.index('--source-ref')+1],'refs/heads/main')
            self.assertEqual(args[args.index('--signer-workflow')+1],'closure-labs/maestro/.github/workflows/release.yml')
            self.assertIn('--deny-self-hosted-runners',args)
            return [{'verificationResult':{'statement':good}}]
        with patch.object(pub.native,'response',side_effect=response):writer.receipt_attestation(pub.native,path,revision)
        for changed in (dict(good,predicateType='unsupported'),dict(good,subject=[{'name':'other.json','digest':{'sha256':pub.native.file_hash(path)}}])):
            with self.subTest(changed=changed),patch.object(pub.native,'response',return_value=[{'verificationResult':{'statement':changed}}]),self.assertRaises(ValueError):
                writer.receipt_attestation(pub.native,path,revision)

    def test_receipt_signature_transport_failure_and_mutation_fail_closed(self):
        def failed(*args):raise subprocess.CalledProcessError(1,args)
        with self.assertRaises(subprocess.CalledProcessError):self.publish(verify_receipt=failed)
        def changed(native,path,revision):path.write_bytes(b'changed after verification')
        with self.assertRaises(ValueError):self.publish(verify_receipt=changed)
        self.assertEqual(self.calls,[]);self.assertEqual(self.published,[])
        self.assertFalse(list(self.case.root.glob('.native-release-writer-*')))

    def test_real_final_name_verifier_requires_provenance_and_exact_spdx_predicate(self):
        gh=self.case.case.case.bin/'gh'
        gh.write_text('#!'+sys.executable+'\n'+"""import json,sys,os
from pathlib import Path
args=sys.argv[1:]
assert args[:2]==['attestation','verify']
assert '--deny-self-hosted-runners' in args
assert args[args.index('--signer-workflow')+1]=='closure-labs/maestro/.github/workflows/release.yml'
assert args[args.index('--source-digest')+1]=='a'*40
kind=args[args.index('--predicate-type')+1]
iso=Path(args[2]);import hashlib
digest=hashlib.sha256(iso.read_bytes()).hexdigest()
predicate=json.loads(Path('candidate/maestro-system.spdx.json').read_text()) if kind.endswith('Document/v2.3') else {}
if os.environ.get('FORGE_SPDX') and predicate:predicate={'spdxVersion':'SPDX-2.3','forged':True}
print(json.dumps([{'verificationResult':{'statement':{'subject':[{'name':iso.name,'digest':{'sha256':digest}}],'predicateType':kind,'predicate':predicate}}}]))
""");gh.chmod(0o700)
        def execute(args,**kwargs):
            self.assertEqual(args,['maestro-ci-release-attestations'])
            return subprocess.run([shutil.which('bash'),str(ROOT/'modules/release/publication/_source/release-attestations.sh')],**kwargs)
        self.assertEqual(self.publish(execute=execute,verify_receipt=None)['status'],'published')
        self.published.clear()
        with patch.dict(self.env,FORGE_SPDX='true'),self.assertRaises(subprocess.CalledProcessError):self.publish(execute=execute,verify_receipt=None)
        self.assertEqual(self.published,[])

    def test_partial_release_cli_identity_rejects_before_network(self):
        source=ROOT/'modules/ci/security/_source/native-publication.py'
        for op,extra in [('release',[]),('release',['--release-directory','unverified']),('check',['--release-directory','x','--release-iso','y'])]:
            p=subprocess.run([sys.executable,str(source),op,'--run','7','--attempt','1','--revision','a'*40,*extra],env=dict(os.environ,GH_TOKEN=''),capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,2,p.stdout+p.stderr)
            self.assertIn('"error": "ValueError"',p.stderr)
    def test_mandatory_high_critical_unknown_blocks_before_release_module_or_write(self):
        for severity in ('high','critical','unknown'):
            self.case.case.findings=[self.case.case.finding(severity)];bundle=self.case.case.bundle()
            with self.subTest(severity=severity),patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.case.api),patch.object(pub,'module',side_effect=AssertionError('Writer must not load')):
                with self.assertRaises(ValueError):pub.consume(bundle,self.case.case.policy_path,'release',release={'directory':self.case.output,'iso':self.final})
        self.assertEqual(self.published,[])

if __name__=='__main__':unittest.main()
