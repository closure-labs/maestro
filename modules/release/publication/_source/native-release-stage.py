#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive local release assets from exact signed native data; no public writes."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import threading

spec=importlib.util.spec_from_file_location('native_publication',os.environ['MAESTRO_NATIVE_PUBLICATION_SOURCE'])
publication=importlib.util.module_from_spec(spec);spec.loader.exec_module(publication)
native=publication.native
MAX_ISO=32*1024**3


class DiskMonitor:
    """Bounded hosted filesystem sampling; observed high water is not exact peak."""
    def __init__(self,path,enabled):
        self.path=path;self.enabled=enabled;self.stop=threading.Event()
        self.samples=0;self.minimum=None;self.error=None
    def sample(self):
        try:
            free=shutil.disk_usage(self.path).free
            self.minimum=free if self.minimum is None else min(self.minimum,free)
            self.samples+=1
        except OSError as error:self.error=error
    def loop(self):
        while not self.stop.wait(.1):self.sample()
    def __enter__(self):
        if self.enabled:
            self.sample();self.thread=threading.Thread(target=self.loop,daemon=True);self.thread.start()
        return self
    def snapshot(self):
        self.sample()
        native.require(self.error is None,'Disk measurement failed')
        return dict(sampleIntervalSeconds=.1,samples=self.samples,minimumObservedFreeBytes=self.minimum,
            exactPeak=False)
    def __exit__(self,*args):
        if self.enabled:self.stop.set();self.thread.join()


def freeze_iso(source,target):
    with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        info=os.fstat(stream.fileno())
        native.require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=MAX_ISO,'Bounded regular installer ISO required')
        native.require(shutil.disk_usage(target.parent).free>=3*info.st_size+256*1024**2,'Insufficient release-staging disk headroom')
        digest=hashlib.sha256();remaining=info.st_size
        with target.open('xb') as out:
            while remaining:
                block=stream.read(min(1024**2,remaining));native.require(block,'ISO shrank during snapshot')
                remaining-=len(block);digest.update(block);out.write(block)
            native.require(not stream.read(1),'ISO grew during snapshot')
        return digest.hexdigest()


def stage(bundle,iso,media,output,version,policy_path,execute=native.operations.run,attest=native.attest,trusted=native.trusted_run,final_iso=None,findings_review=False,qualification_only=False):
    native.require(not (findings_review and qualification_only),
        "Qualification cannot accept findings")
    native.require(not qualification_only or final_iso is not None,
        "Qualification requires the exact final-name ISO snapshot")
    started=time.monotonic();disk_samples=[]
    def sample(phase):
        if qualification_only:
            disk_samples.append(dict(phase=phase,elapsedSeconds=time.monotonic()-started,
                freeBytes=shutil.disk_usage(output.parent).free))
    native.require(not output.exists() and not output.is_symlink(),'New release output required')
    native.require(isinstance(version,str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',version),'Exact supported release version required')
    if final_iso is not None:
        native.require(final_iso.name=='maestro-v'+version+'.iso'
            and final_iso.parent.resolve()==output.parent.resolve()
            and not final_iso.exists() and not final_iso.is_symlink(),
            'New exact versioned ISO sibling required')
    revision=bundle['receipt']['sourceRevision']
    remote=publication.risk.contents(native.api,'VERSION',revision).decode().strip()
    native.require(version==remote,'Release version differs from protected exact source')
    # Neither staging nor its receipt grants publication authority.
    policy_digest=native.file_hash(policy_path)
    # The explicit route verifies the same release-specific fresh human gate;
    # its flag alone grants nothing. Standalone staging keeps the strict default.
    outcome=publication.consume(bundle,policy_path,'release-qualify' if qualification_only else 'release-stage' if findings_review else 'check')
    expected=bundle['receipt'].get('bootOrigin') or dict(revision=revision,runId=bundle['receipt']['runId'],runAttempt=bundle['receipt']['runAttempt'])
    native.require(media==(expected['runId'],expected['runAttempt'],expected['revision']),
                   'Exact original executed-boot media producer required')
    inventory_iso=bundle['binding'].get('isoSha256')
    if inventory_iso is None:
        boot=bundle['result']['boot'];transfer=bundle['result'].get('inventoryTransferSha256','')
        receipt=bundle['result'].get('inventoryIsoBinding')
        current=native.origin_identity(bundle['receipt']['runId'],bundle['receipt']['runAttempt'],revision)
        native.require(boot.get('disposition')=='verified-retained' and re.fullmatch(r'[0-9a-f]{64}',transfer)
            and isinstance(receipt,dict) and type(receipt.get('schemaVersion')) is int
            and receipt==dict(schemaVersion=1,producer=current,
                inventorySha256=transfer,isoSha256=boot['isoSha256']), 'Missing exact reused ISO/inventory receipt')
        inventory_iso=boot['isoSha256']
    trusted(*media)
    output.parent.mkdir(parents=True,exist_ok=True)
    sample('before-snapshot')
    with DiskMonitor(output.parent,qualification_only) as monitor, tempfile.TemporaryDirectory(prefix='.maestro-release-',dir=output.parent) as temporary:
        work=Path(temporary);frozen=work/'maestro-installer.iso';digest=freeze_iso(iso,frozen)
        native.require(digest==inventory_iso==bundle['result']['boot']['isoSha256'],
                       'Installer bytes differ from authenticated inventory/boot proof')
        attest(frozen,media[2])
        sample('verified-snapshot')
        staged=work/'release';staged.mkdir();tag='v'+version
        execute(['maestro-ci-release-stage',str(frozen),str(work/('maestro-'+tag+'.iso')),str(staged)],check=True,timeout=900,
                env=dict(os.environ,MAESTRO_RELEASE_PART_SIZE='1900M',MAESTRO_RELEASE_ASSET_LIMIT='2147483648'))
        for kind in ('spdx','cdx'):
            name='maestro-'+tag+'.'+kind+'.json.gz';target=staged/name
            with (bundle['directory']/('maestro-system.'+kind+'.json')).open('rb') as source,target.open('xb') as out:
                with gzip.GzipFile(filename='',mode='wb',fileobj=out,mtime=0) as compressed:shutil.copyfileobj(source,compressed,1024**2)
            (staged/(name+'.sha256')).write_text(native.file_hash(target)+'  '+name+'\n')
        # Verify splitter outputs against the exact authenticated ISO, rather
        # than treating successful exit or metadata as a byte-verification claim.
        parts=sorted(staged.glob('maestro-'+tag+'.iso.part-*'));native.require(0<len(parts)<=18,'Missing or excessive installer parts')
        joined=hashlib.sha256()
        for index,path in enumerate(parts,1):
            native.require(path.name=='maestro-'+tag+'.iso.part-'+f'{index:02d}' and path.is_file() and not path.is_symlink(),
                           'Changed installer part sequence')
            native.require(0<path.stat().st_size<2147483648,'Installer part exceeds existing asset bound')
            with path.open('rb') as stream:
                while block:=stream.read(1024**2):joined.update(block)
        native.require(joined.hexdigest()==digest,'Split installer bytes differ from authenticated ISO')
        checksum=staged/('maestro-'+tag+'.iso.sha256')
        native.require(checksum.read_text()==digest+'  maestro-'+tag+'.iso\n','Changed installer checksum')
        allowed={p.name for p in parts}|{checksum.name}|{'maestro-'+tag+'.'+kind+'.json.gz'+suffix for kind in ('spdx','cdx') for suffix in ('','.sha256')}
        native.require({p.name for p in staged.iterdir()}==allowed and all(p.is_file() and not p.is_symlink() for p in staged.iterdir()),
                       'Unexpected or nonregular release asset')
        assets={p.name:dict(sha256=native.file_hash(p),size=p.stat().st_size) for p in sorted(staged.iterdir())}
        if final_iso is not None:
            # Retain this invocation's private byte snapshot, never a link to
            # the caller's mutable download or an extra full-size ISO copy.
            native.require(frozen.is_file() and not frozen.is_symlink()
                and native.file_hash(frozen)==digest, 'Versioned ISO snapshot changed during staging')
        publication.fresh(bundle,policy_path,policy_digest)
        sample('verified-assets-and-snapshot')
        receipt=dict(schemaVersion=1,status='staged-native-release-assets',authorization=False,publicationReady=False,
            sourceRevision=revision,sourceRun=bundle['receipt']['runId'],sourceAttempt=bundle['receipt']['runAttempt'],
            mediaProducer=dict(runId=media[0],runAttempt=media[1],revision=media[2]),version=version,tag=tag,
            isoSha256=digest,isoBytesVerified=True,narBytesVerified=False,assets=assets,verdict=outcome['verdict'])
        if 'policyRevision' in bundle['receipt']:receipt['policyRevision']=bundle['receipt']['policyRevision']
        if 'healthManifest' in bundle:receipt['healthProducer']=bundle['healthManifest']['producer']
        if final_iso is not None:
            receipt['versionedIso']=dict(filename=final_iso.name,sha256=digest,size=frozen.stat().st_size,
                requiresFinalNameAttestation=True)
        if qualification_only:
            receipt.update(status='nonpublishing-release-qualification-assets',findingsAccepted=False,
                qualification=outcome['review'],
                measurements=dict(elapsedSeconds=time.monotonic()-started,diskSamples=disk_samples,
                    sampling='phase-boundaries-and-periodic-not-exact-peak',diskMonitor=monitor.snapshot(),isoBytes=frozen.stat().st_size,
                    stagedAssetBytes=sum(row['size'] for row in assets.values())),
                finalNameAttestationsCreated=False)
        (staged/'native-release-staging.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')
        native.require(not output.exists() and not output.is_symlink(),'Release output appeared during staging')
        linked=False
        snapshot_info=frozen.lstat() if final_iso is not None else None
        try:
            if final_iso is not None:
                os.link(frozen,final_iso,follow_symlinks=False)
                linked=True
            os.rename(staged,output)
        except BaseException:
            if linked:
                try:
                    if os.path.samestat(final_iso.lstat(),snapshot_info):final_iso.unlink()
                except FileNotFoundError:pass
            raise
        return receipt


def verify_qualification(bundle,directory,iso,version,policy_path,execute=native.operations.run):
    """Read back final-name signatures; no publisher/closure/cache writer call."""
    outcome=publication.consume(bundle,policy_path,'release-qualify')
    native.require(directory.is_dir() and not directory.is_symlink(),'Regular qualification directory required')
    receipt_path=directory/'native-release-staging.json'
    native.require(receipt_path.is_file() and not receipt_path.is_symlink()
        and 0<receipt_path.stat().st_size<=1024**2,'Bounded qualification receipt required')
    receipt=publication.risk.parse(receipt_path.read_bytes())
    native.require(receipt.get('status')=='nonpublishing-release-qualification-assets'
        and receipt.get('authorization') is False and receipt.get('publicationReady') is False
        and receipt.get('findingsAccepted') is False and receipt.get('version')==version
        and receipt.get('qualification')==outcome['review']
        and receipt.get('sourceRevision')==bundle['receipt']['sourceRevision']
        and receipt.get('sourceRun')==bundle['receipt']['runId']
        and receipt.get('sourceAttempt')==bundle['receipt']['runAttempt'], 'Exact qualification receipt required')
    native.require(iso.name=='maestro-v'+version+'.iso' and iso.is_file() and not iso.is_symlink()
        and native.file_hash(iso)==receipt.get('isoSha256')==bundle['result']['boot']['isoSha256'],
        'Qualification final subject changed')
    policy_digest=native.file_hash(policy_path)
    # Small bounded verifier layout only; hard-link the same final ISO, no copy.
    with tempfile.TemporaryDirectory(prefix='.maestro-qualification-',dir=iso.parent) as temporary:
        work=Path(temporary);(work/'release').mkdir();(work/'candidate').mkdir()
        os.link(iso,work/iso.name,follow_symlinks=False)
        (work/'release'/(iso.name+'.sha256')).write_text(receipt['isoSha256']+'  '+iso.name+'\n')
        shutil.copyfile(bundle['directory']/'maestro-system.spdx.json',work/'candidate/maestro-system.spdx.json')
        execute(['maestro-ci-release-attestations'],check=True,timeout=300,cwd=work,
            env=dict(os.environ,RUNNER_TEMP=str(work),RELEASE_TAG='v'+version,
                SOURCE_SHA=bundle['receipt'].get('policyRevision',bundle['receipt']['sourceRevision'])))
        native.require(native.file_hash(work/iso.name)==receipt['isoSha256'],'Qualification subject changed during readback')
    publication.fresh(bundle,policy_path,policy_digest)
    result=dict(status='nonpublishing-release-qualification-verified',authorization=False,publicationReady=False,
        findingsAccepted=False,isoSha256=receipt['isoSha256'],finalNameAttestationsVerified=True,
        qualification=outcome['review'],verdict=outcome['verdict'])
    target=Path(os.environ['NATIVE_RESULT_FILE'])
    with target.open('x') as stream:stream.write(json.dumps(result,sort_keys=True)+'\n')
    return result


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--directory',type=Path);cli.add_argument('--iso',type=Path,required=True)
    cli.add_argument('--run',type=int,required=True);cli.add_argument('--attempt',type=int,required=True);cli.add_argument('--revision',required=True)
    cli.add_argument('--media-run',type=int,required=True);cli.add_argument('--media-attempt',type=int,required=True);cli.add_argument('--media-revision',required=True)
    cli.add_argument('--version',required=True);cli.add_argument('--output',type=Path,required=True)
    cli.add_argument('--health-run',type=int);cli.add_argument('--health-attempt',type=int);cli.add_argument('--health-directory',type=Path)
    cli.add_argument('--policy-revision',help='Explicit current main policy for this exact qualified product')
    cli.add_argument('--verify-qualification',action='store_true',help='Read back final-name attestations for an existing qualification only')
    cli.add_argument('--qualification-only',action='store_true',help='Nonpublishing exact-byte staging trial; accepts no findings and produces no publication-capable receipt')
    cli.add_argument('--findings-review',action='store_true',help='Require the current release-specific protected human findings review before local staging; grants no publication authority')
    cli.add_argument('--final-iso',type=Path,help='Keep verified versioned ISO sibling for subsequent native GitHub attestation; no publication')
    cli.add_argument('--boot-origin-run',type=int);cli.add_argument('--boot-origin-attempt',type=int);cli.add_argument('--boot-origin-revision')
    args=cli.parse_args()
    native.require(not args.verify_qualification or args.qualification_only,'Readback is qualification-only')
    native.require(not (args.findings_review and args.qualification_only),'Qualification cannot accept findings')
    native.require(not args.qualification_only or args.final_iso is not None,'Qualification needs final-name ISO')
    origin=(args.boot_origin_run,args.boot_origin_attempt,args.boot_origin_revision)
    native.require(args.policy_revision is None or re.fullmatch(r'[0-9a-f]{40}',args.policy_revision),'Exact explicit policy revision required')
    native.require(all(v is None for v in origin) or all(v is not None for v in origin),'Complete original boot tuple required')
    origin=None if all(v is None for v in origin) else origin
    with native.operations.budget(3300),publication.selected(args.directory,args.run,args.attempt,args.revision,origin,
        policy_revision=args.policy_revision,health_run=args.health_run,health_attempt=args.health_attempt,
        health_directory=args.health_directory) as bundle:
        if args.verify_qualification:
            result=verify_qualification(bundle,args.output,args.final_iso,args.version,Path(os.environ['MAESTRO_NATIVE_SECURITY_POLICY']))
        else:result=stage(bundle,args.iso,(args.media_run,args.media_attempt,args.media_revision),args.output,args.version,Path(os.environ['MAESTRO_NATIVE_SECURITY_POLICY']),final_iso=args.final_iso,findings_review=args.findings_review,qualification_only=args.qualification_only)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except (ValueError,KeyError,TypeError,OSError,MemoryError,subprocess.SubprocessError) as error:
        raise SystemExit('Native release staging blocked: '+type(error).__name__)
