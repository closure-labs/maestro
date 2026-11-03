#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded real splitter and native policy/ISO rejection boundaries."""
import gzip
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=module('publication_fixture',ROOT/'modules/ci/security/_tests/native-publication.py')
with patch.dict(os.environ,MAESTRO_NATIVE_PUBLICATION_SOURCE=str(ROOT/'modules/ci/security/_source/native-publication.py')):
    release=module('release_stage',ROOT/'modules/release/publication/_source/native-release-stage.py')
pub=release.publication

class ReleaseStage(unittest.TestCase):
    def setUp(self):
        self.case=fixture.Publication();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.root=self.case.case.root;self.bundle=self.case.bundle()
        self.iso=self.root/'input.iso';self.iso.write_bytes(b'bounded fixture ISO\x00'*100)
        digest=pub.native.file_hash(self.iso)
        self.bundle.update(binding=dict(isoSha256=digest),result=dict(boot=dict(isoSha256=digest)))
        self.bundle['receipt']['runAttempt']=1
        self.output=self.root/'output';self.media=(7,1,fixture.fixture.SHA);self.calls=[]
        bash=os.environ.get('BASH') or '/bin/bash'
        # The isolated build has no /bin/bash; use its declared PATH tool.
        import shutil
        bash=shutil.which('bash') or bash
        wrapper=self.case.case.bin/'maestro-ci-release-stage'
        wrapper.write_text('#!'+bash+'\nexec '+shlex.quote(bash)+' '+shlex.quote(str(ROOT/'modules/release/publication/_source/release-split.sh'))+' "$@"\n');wrapper.chmod(0o700)
        self.env=dict(self.case.env,PATH=str(self.case.case.bin)+os.pathsep+os.environ['PATH'])
        self.bundle['directory'].joinpath('maestro-system.spdx.json').write_text('{"spdxVersion":"SPDX-2.3"}')
        self.bundle['directory'].joinpath('maestro-system.cdx.json').write_text('{"bomFormat":"CycloneDX"}')
    def api(self,path):
        if path.startswith('contents/VERSION?ref='):return dict(encoding='base64',size=6,content='My4yLjAK')
        return self.case.api(path)
    def execute(self,args,**kwargs):
        self.calls.append('split')
        return subprocess.run(args,**kwargs)
    def stage(self,**kwargs):
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
            return release.stage(self.bundle,self.iso,self.media,self.output,'3.2.0',self.case.policy_path,
                execute=kwargs.pop('execute',self.execute),attest=lambda *a:self.calls.append('attest'),trusted=lambda *a:self.calls.append('trusted'),**kwargs)
    def test_actual_splitter_keeps_exact_iso_and_authenticated_sboms(self):
        result=self.stage();self.assertEqual(self.calls,['trusted','attest','split'])
        self.assertTrue(result['isoBytesVerified']);self.assertFalse(result['narBytesVerified'])
        self.assertFalse(result['authorization']);self.assertFalse(result['publicationReady'])
        self.assertEqual((self.output/'maestro-v3.2.0.iso.part-01').read_bytes(),self.iso.read_bytes())
        for kind in ('spdx','cdx'):
            self.assertEqual(gzip.decompress((self.output/('maestro-v3.2.0.'+kind+'.json.gz')).read_bytes()),
                (self.bundle['directory']/('maestro-system.'+kind+'.json')).read_bytes())
        for name,record in result['assets'].items():self.assertEqual(pub.native.file_hash(self.output/name),record['sha256'])
    def test_versioned_iso_handoff_is_a_verified_snapshot_not_a_public_asset(self):
        final=self.root/'maestro-v3.2.0.iso';inodes=[]
        def execute(args,**kwargs):
            inodes.append(Path(args[1]).stat().st_ino)
            return self.execute(args,**kwargs)
        result=self.stage(final_iso=final,execute=execute)
        self.assertEqual(final.read_bytes(),self.iso.read_bytes())
        self.assertEqual(final.stat().st_ino,inodes[0])
        self.assertNotEqual(final.stat().st_ino,self.iso.stat().st_ino)
        self.assertEqual(result['versionedIso'],dict(filename=final.name,
            sha256=pub.native.file_hash(final),size=final.stat().st_size,requiresFinalNameAttestation=True))
        self.assertNotIn(final.name,result['assets'])
        self.assertFalse(result['authorization']);self.assertFalse(result['publicationReady'])
        self.iso.write_bytes(b'caller changes the original download')
        self.assertEqual(pub.native.file_hash(final),result['isoSha256'])

    def test_versioned_iso_wrong_name_parent_existing_and_symlink_reject(self):
        final=self.root/'maestro-v3.2.0.iso'
        for path in (self.root/'wrong.iso',self.root/'other'/'maestro-v3.2.0.iso'):
            with self.subTest(path=path),self.assertRaises(ValueError):self.stage(final_iso=path)
        final.write_bytes(b'preexisting')
        with self.assertRaises(ValueError):self.stage(final_iso=final)
        self.assertEqual(final.read_bytes(),b'preexisting');final.unlink()
        final.symlink_to(self.root/'missing')
        with self.assertRaises(ValueError):self.stage(final_iso=final)
        self.assertTrue(final.is_symlink());self.assertFalse(self.output.exists())
        self.assertEqual(self.calls,[])

    def test_versioned_iso_snapshot_substitution_rejects_before_handoff(self):
        final=self.root/'maestro-v3.2.0.iso'
        def changed(args,**kwargs):
            self.execute(args,**kwargs);Path(args[1]).write_bytes(b'changed snapshot')
        with self.assertRaises(ValueError):self.stage(final_iso=final,execute=changed)
        self.assertFalse(final.exists());self.assertFalse(self.output.exists())

    def test_versioned_iso_link_or_directory_commit_failure_cleans_only_own_output(self):
        final=self.root/'maestro-v3.2.0.iso'
        for operation in ('link','rename'):
            with self.subTest(operation=operation),patch.object(release.os,operation,side_effect=OSError('fixture failure')):
                with self.assertRaises(OSError):self.stage(final_iso=final)
            self.assertFalse(final.exists());self.assertFalse(self.output.exists())
            self.assertFalse(list(self.root.glob('.maestro-release-*')))

    def test_versioned_iso_cleanup_preserves_a_replaced_subject(self):
        final=self.root/'maestro-v3.2.0.iso'
        def failed_commit(*args):
            final.unlink();final.write_bytes(b'replacement from another operation')
            raise OSError('fixture commit failure')
        with patch.object(release.os,'rename',side_effect=failed_commit),self.assertRaises(OSError):
            self.stage(final_iso=final)
        self.assertEqual(final.read_bytes(),b'replacement from another operation')
        self.assertFalse(self.output.exists())

    def test_final_iso_shell_argument_is_opt_in_and_forwarded_without_execution(self):
        import shutil
        subject=self.root/'maestro-v3.2.0.iso';captured=self.root/'argv.json'
        adapter=self.root/'capture.py'
        adapter.write_text('import json,os,sys\nfrom pathlib import Path\nPath(os.environ["CAPTURE_ARGS"]).write_text(json.dumps(sys.argv[1:]))\n')
        environment=dict(os.environ,MAESTRO_NATIVE_RELEASE_STAGE_SOURCE=str(adapter),CAPTURE_ARGS=str(captured),
            NATIVE_DIRECTORY='bundle',NATIVE_ISO='source.iso',NATIVE_RELEASE_OUTPUT='assets',
            NATIVE_RELEASE_VERSION='3.2.0',NATIVE_RUN='7',NATIVE_ATTEMPT='1',NATIVE_REVISION=fixture.fixture.SHA,
            NATIVE_MEDIA_RUN='7',NATIVE_MEDIA_ATTEMPT='1',NATIVE_MEDIA_REVISION=fixture.fixture.SHA)
        for final in ('',str(subject)):
            environment.update(NATIVE_RELEASE_FINAL_ISO=final,NATIVE_POLICY_REVISION='e'*40)
            subprocess.run([shutil.which('bash'),str(ROOT/'modules/release/publication/_source/native-release-stage.sh')],
                env=environment,check=True,capture_output=True,timeout=5)
            args=json.loads(captured.read_text())
            self.assertEqual('--final-iso' in args,bool(final))
            if final:self.assertEqual(args[args.index('--final-iso')+1],final)
            self.assertEqual(args[args.index('--revision')+1],fixture.fixture.SHA)
            self.assertEqual(args[args.index('--policy-revision')+1],'e'*40)
        self.assertFalse(subject.exists());self.assertFalse(self.output.exists())

    def test_versioned_iso_race_never_overwrites_an_existing_subject(self):
        final=self.root/'maestro-v3.2.0.iso'
        def appeared(args,**kwargs):
            self.execute(args,**kwargs);final.write_bytes(b'another invocation')
        with self.assertRaises(FileExistsError):self.stage(final_iso=final,execute=appeared)
        self.assertEqual(final.read_bytes(),b'another invocation')
        self.assertFalse(self.output.exists())

    def test_older_product_uses_its_version_and_the_explicit_current_policy(self):
        policy_revision='e'*40;self.bundle['receipt']['policyRevision']=policy_revision;observed=[];original_api=self.api
        def api(path):
            observed.append(path)
            if path=='git/ref/heads/main':return dict(object=dict(sha=policy_revision))
            return original_api(path)
        with patch.object(self,'api',side_effect=api):
            result=self.stage(final_iso=self.root/'maestro-v3.2.0.iso')
        self.assertEqual(result['sourceRevision'],fixture.fixture.SHA)
        self.assertEqual(result['policyRevision'],policy_revision)
        self.assertIn('contents/VERSION?ref='+fixture.fixture.SHA,observed)
        self.assertIn('contents/'+pub.POLICY+'?ref='+policy_revision,observed)
        self.assertFalse(result['authorization']);self.assertFalse(result['publicationReady'])

    def test_high_findings_block_before_iso_or_producer_operations(self):
        self.case.findings=[self.case.finding('critical')];self.bundle=self.case.bundle()
        with self.assertRaises(pub.MandatoryVerdictError):self.stage()
        self.assertEqual(self.calls,[]);self.assertFalse(self.output.exists())
        subject=self.root/'maestro-v3.2.0.iso'
        with self.assertRaises(pub.MandatoryVerdictError):self.stage(final_iso=subject)
        self.assertFalse(subject.exists());self.assertEqual(self.calls,[])
    def reused_inventory(self):
        self.bundle['binding']['isoSha256']=None
        self.bundle['result'].update(inventoryTransferSha256='e'*64,
            inventoryIsoBinding=dict(schemaVersion=1,producer=pub.native.origin_identity(7,1,fixture.fixture.SHA),
                inventorySha256='e'*64,isoSha256=pub.native.file_hash(self.iso)))
        self.bundle['result']['boot']['disposition']='verified-retained'
        self.bundle['receipt']['bootOrigin']=dict(runId=8,runAttempt=2,revision='b'*40)
        self.media=(8,2,'b'*40)
    def test_reused_inventory_receipt_keeps_original_proof_and_exact_iso_byte_check(self):
        self.reused_inventory();subject=self.root/'maestro-v3.2.0.iso';result=self.stage(final_iso=subject)
        self.assertEqual(pub.native.file_hash(subject),result['isoSha256'])
        self.assertTrue(result['isoBytesVerified']);self.assertFalse(result['authorization'])
        self.assertEqual(result['mediaProducer'],dict(runId=8,runAttempt=2,revision='b'*40))
        self.assertEqual(result['isoSha256'],pub.native.file_hash(self.iso))
        self.assertEqual(self.calls,['trusted','attest','split'])
    def test_reused_inventory_cannot_omit_or_substitute_producer_transfer_or_iso_receipt(self):
        for field,value in [('producer',{}),('inventorySha256','f'*64),('isoSha256','f'*64),('schemaVersion',2),('schemaVersion',True)]:
            self.reused_inventory();self.bundle['result']['inventoryIsoBinding'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.stage()
            self.assertEqual(self.calls,[]);self.assertFalse(self.output.exists())
        self.reused_inventory();self.bundle['result'].pop('inventoryIsoBinding')
        with self.assertRaises(ValueError):self.stage()
        self.reused_inventory();self.bundle['result']['boot']['disposition']='executed'
        with self.assertRaises(ValueError):self.stage()
        self.assertEqual(self.calls,[])
    def test_wrong_version_or_original_media_cannot_stage(self):
        self.media=(8,1,fixture.fixture.SHA)
        with self.assertRaises(ValueError):self.stage()
        self.assertEqual(self.calls,[])
        self.media=(7,1,fixture.fixture.SHA)
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
            with self.assertRaises(ValueError):release.stage(self.bundle,self.iso,self.media,self.output,'3.2.1',self.case.policy_path)
        self.assertFalse(self.output.exists())
    def test_hash_mismatch_symlink_and_oversize_reject(self):
        self.iso.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.stage()
        self.assertNotIn('attest',self.calls);self.assertFalse(self.output.exists())
        original=self.root/'real';self.iso.rename(original);self.iso.symlink_to(original)
        with self.assertRaises(OSError):self.stage()
        self.iso.unlink();self.iso.write_bytes(b'x'*32)
        with patch.object(release,'MAX_ISO',16):
            with self.assertRaises(ValueError):self.stage()
    def test_attestation_and_splitter_failures_never_leave_output(self):
        with patch.dict(os.environ,self.env),patch.object(pub.native,'api',side_effect=self.api):
            with self.assertRaises(ValueError):release.stage(self.bundle,self.iso,self.media,self.output,'3.2.0',self.case.policy_path,
                attest=lambda *a:(_ for _ in ()).throw(ValueError('forged')),trusted=lambda *a:None)
        def failed(*args,**kwargs):raise subprocess.CalledProcessError(17,args)
        with self.assertRaises(subprocess.CalledProcessError):self.stage(execute=failed)
        self.assertFalse(self.output.exists());self.assertFalse(list(self.root.glob('.maestro-release-*')))
    def test_split_substitution_and_unexpected_assets_reject(self):
        for change in ('bytes','extra','symlink'):
            def execute(args,**kwargs):
                self.execute(args,**kwargs);out=Path(args[-1])
                if change=='bytes':next(out.glob('*.part-*')).write_bytes(b'forged')
                if change=='extra':(out/'unexpected').write_text('x')
                if change=='symlink':(out/'unexpected').symlink_to(self.iso)
            with self.subTest(change=change),self.assertRaises(ValueError):self.stage(execute=execute)
            self.assertFalse(self.output.exists())
    def test_final_main_expiry_or_policy_race_rejects_local_result(self):
        for change in ('main','expiry','policy'):
            original_api=self.api;changed=[False]
            def api(path):
                if changed[0] and change=='main' and path=='git/ref/heads/main':return dict(object=dict(sha='f'*40))
                return original_api(path)
            def execute(args,**kwargs):
                self.execute(args,**kwargs);changed[0]=True
                if change=='expiry':self.bundle['scans']['expiresAt']='1970-01-01T00:00:00Z'
                if change=='policy':self.case.policy_path.write_text('{}')
            self.case.policy_path.write_text(json.dumps(self.case.policy))
            old_expiry=self.bundle['scans']['expiresAt']
            subject=self.root/'maestro-v3.2.0.iso'
            with patch.object(self,'api',side_effect=api),self.subTest(change=change),self.assertRaises(ValueError):self.stage(execute=execute,final_iso=subject)
            self.assertFalse(subject.exists())
            self.assertFalse(self.output.exists());self.bundle['scans']['expiresAt']=old_expiry
    def test_disk_headroom_and_existing_output_fail_closed(self):
        with patch.object(release.shutil,'disk_usage',return_value=type('Disk',(),dict(free=1))()):
            with self.assertRaises(ValueError):self.stage()
        self.output.mkdir()
        with self.assertRaises(ValueError):self.stage()
        self.assertEqual(list(self.output.iterdir()),[])

if __name__=='__main__':unittest.main()
