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

spec=importlib.util.spec_from_file_location('native_publication',os.environ['MAESTRO_NATIVE_PUBLICATION_SOURCE'])
publication=importlib.util.module_from_spec(spec);spec.loader.exec_module(publication)
native=publication.native
MAX_ISO=32*1024**3


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


def stage(bundle,iso,media,output,version,policy_path,execute=native.operations.run,attest=native.attest,trusted=native.trusted_run,final_iso=None):
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
    outcome=publication.consume(bundle,policy_path,'check')
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
    with tempfile.TemporaryDirectory(prefix='.maestro-release-',dir=output.parent) as temporary:
        work=Path(temporary);frozen=work/'maestro-installer.iso';digest=freeze_iso(iso,frozen)
        native.require(digest==inventory_iso==bundle['result']['boot']['isoSha256'],
                       'Installer bytes differ from authenticated inventory/boot proof')
        attest(frozen,media[2])
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
        receipt=dict(schemaVersion=1,status='staged-native-release-assets',authorization=False,publicationReady=False,
            sourceRevision=revision,sourceRun=bundle['receipt']['runId'],sourceAttempt=bundle['receipt']['runAttempt'],
            mediaProducer=dict(runId=media[0],runAttempt=media[1],revision=media[2]),version=version,tag=tag,
            isoSha256=digest,isoBytesVerified=True,narBytesVerified=False,assets=assets,verdict=outcome['verdict'])
        if 'policyRevision' in bundle['receipt']:receipt['policyRevision']=bundle['receipt']['policyRevision']
        if final_iso is not None:
            receipt['versionedIso']=dict(filename=final_iso.name,sha256=digest,size=frozen.stat().st_size,
                requiresFinalNameAttestation=True)
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


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--directory',type=Path,required=True);cli.add_argument('--iso',type=Path,required=True)
    cli.add_argument('--run',type=int,required=True);cli.add_argument('--attempt',type=int,required=True);cli.add_argument('--revision',required=True)
    cli.add_argument('--media-run',type=int,required=True);cli.add_argument('--media-attempt',type=int,required=True);cli.add_argument('--media-revision',required=True)
    cli.add_argument('--version',required=True);cli.add_argument('--output',type=Path,required=True)
    cli.add_argument('--policy-revision',help='Explicit current main policy for this exact qualified product')
    cli.add_argument('--final-iso',type=Path,help='Keep verified versioned ISO sibling for subsequent native GitHub attestation; no publication')
    cli.add_argument('--boot-origin-run',type=int);cli.add_argument('--boot-origin-attempt',type=int);cli.add_argument('--boot-origin-revision')
    args=cli.parse_args();origin=(args.boot_origin_run,args.boot_origin_attempt,args.boot_origin_revision)
    native.require(args.policy_revision is None or re.fullmatch(r'[0-9a-f]{40}',args.policy_revision),'Exact explicit policy revision required')
    native.require(all(v is None for v in origin) or all(v is not None for v in origin),'Complete original boot tuple required')
    origin=None if all(v is None for v in origin) else origin
    with native.operations.budget(3300),native.verified_bundle(args.directory,args.run,args.attempt,args.revision,
        Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY']),origin,publication=True,policy_revision=args.policy_revision) as bundle:
        result=stage(bundle,args.iso,(args.media_run,args.media_attempt,args.media_revision),args.output,args.version,Path(os.environ['MAESTRO_NATIVE_SECURITY_POLICY']),final_iso=args.final_iso)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except (ValueError,KeyError,TypeError,OSError,MemoryError,subprocess.SubprocessError) as error:
        raise SystemExit('Native release staging blocked: '+type(error).__name__)
