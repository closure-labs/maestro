#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive native release writer; reuse release operations, never ledger admission."""
import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile


def receipt_attestation(native,path,revision):
    verified=native.response('attestation','verify',str(path),'--repo',native.REPO,
        '--signer-workflow',native.REPO+'/.github/workflows/release.yml',
        '--source-ref','refs/heads/main','--source-digest',revision,'--signer-digest',revision,
        '--deny-self-hosted-runners','--predicate-type','https://slsa.dev/provenance/v1','--format','json')
    digest=native.file_hash(path)
    native.require(isinstance(verified,list) and any(isinstance(row,dict) and
        isinstance(row.get('verificationResult'),dict) and
        isinstance(row['verificationResult'].get('statement'),dict) and
        row['verificationResult']['statement'].get('predicateType')=='https://slsa.dev/provenance/v1' and
        any(isinstance(subject,dict) and subject.get('name')==path.name and subject.get('digest',{}).get('sha256')==digest
            for subject in row['verificationResult']['statement'].get('subject',[])) for row in verified),
        'Exact signed native release receipt required')


def publish(bundle,directory,iso,policy_path,*,publication=None,assets=None,execute=None,verify_receipt=None):
    # Imported lazily: every caller must first pass native consume()'s mandatory
    # evidence and explicit findings-risk verdict. A staging receipt is data.
    if publication is None:
        import importlib.util
        spec=importlib.util.spec_from_file_location('native_release_publication',os.environ['MAESTRO_NATIVE_PUBLICATION_SOURCE'])
        publication=importlib.util.module_from_spec(spec);spec.loader.exec_module(publication)
    native=publication.native;require=native.require
    revision=bundle['receipt']['sourceRevision'];policy_revision=bundle['receipt'].get('policyRevision',revision)
    require(os.environ.get('MAESTRO_NATIVE_RELEASE_ENABLED')=='true'
        and os.environ.get('GITHUB_REPOSITORY')==native.REPO
        and os.environ.get('GITHUB_REF')=='refs/heads/main'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch'
        and os.environ.get('GITHUB_SHA')==policy_revision,'Native release writer disabled or wrong protected policy context')
    require(bundle.get('_riskAcceptance',{}).get('context',{}).get('operation')=='release',
        'Exact per-publication findings review required before release writes')
    require(bundle.get('inventoryOnly') is not True,'Original inventory cannot authorize publication')
    directory=Path(directory);iso=Path(iso)
    require(directory.is_dir() and not directory.is_symlink(),'Regular staged release directory required')
    manifest=directory/'native-release-staging.json'
    require(manifest.is_file() and not manifest.is_symlink() and 0<manifest.stat().st_size<=1024**2,'Bounded regular staging receipt required')
    with os.fdopen(os.open(manifest,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=1024**2,'Bounded regular staging receipt required')
        raw=stream.read(1024**2+1);require(len(raw)==info.st_size,'Staging receipt changed during read')
    receipt=publication.risk.parse(raw)
    version=publication.risk.contents(native.api,'VERSION',revision).decode().strip()
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',version),'Exact supported product version required')
    tag='v'+version;filename='maestro-'+tag+'.iso'
    digest=bundle['result']['boot']['isoSha256']
    require(receipt.get('schemaVersion')==1 and type(receipt['schemaVersion']) is int
        and receipt.get('status')=='staged-native-release-assets' and receipt.get('authorization') is False
        and receipt.get('publicationReady') is False and receipt.get('sourceRevision')==revision
        and type(receipt.get('sourceRun')) is int and type(receipt.get('sourceAttempt')) is int
        and receipt.get('sourceRun')==bundle['receipt']['runId'] and receipt.get('sourceAttempt')==bundle['receipt']['runAttempt']
        and receipt.get('policyRevision',revision)==policy_revision and receipt.get('version')==version and receipt.get('tag')==tag
        and receipt.get('isoSha256')==digest and receipt.get('isoBytesVerified') is True,
        'Staging receipt differs from verified product identity')
    media=bundle['receipt'].get('bootOrigin') or dict(runId=bundle['receipt']['runId'],
        runAttempt=bundle['receipt']['runAttempt'],revision=revision)
    retained_media=receipt.get('mediaProducer')
    require(isinstance(retained_media,dict) and retained_media==media
        and all(type(retained_media.get(k)) is int for k in ('runId','runAttempt'))
        and receipt.get('narBytesVerified') is False,'Receipt media identity or byte-verification claim differs')
    records=receipt.get('assets');require(isinstance(records,dict),'Exact staged asset inventory required')
    parts=sorted(name for name in records if re.fullmatch(re.escape(filename)+r'\.part-[0-9]{2}',name))
    require(0<len(parts)<=18 and parts==[filename+'.part-'+f'{n:02d}' for n in range(1,len(parts)+1)],'Exact installer part sequence required')
    expected=set(parts)|{filename+'.sha256'}|{'maestro-'+tag+'.'+kind+'.json.gz'+suffix for kind in ('spdx','cdx') for suffix in ('','.sha256')}
    require(set(records)==expected and {p.name for p in directory.iterdir()}==expected|{manifest.name},'Unexpected or missing native release assets')
    require(iso.name==filename and iso.is_file() and not iso.is_symlink(),'Exact regular final-name ISO required')
    require(native.file_hash(iso)==digest and 0<iso.stat().st_size<=32*1024**3,'Final-name ISO differs from authenticated boot bytes')
    total=0
    for name,row in records.items():
        path=directory/name
        require(isinstance(row,dict) and set(row)=={'sha256','size'} and type(row['size']) is int
            and 0<row['size']<2147483648 and re.fullmatch(r'[0-9a-f]{64}',row['sha256']), 'Invalid bounded asset descriptor')
        info=path.lstat();require(stat.S_ISREG(info.st_mode) and info.st_size==row['size'],'Nonregular or resized release asset')
        cap=2147483647 if name in parts else 65*1024**2 if name.endswith('.json.gz') else 512
        require(row['size']<=cap,'Oversized release document/checksum')
        total+=row['size']
    require(total<=32*1024**3+256*1024**2,'Aggregate release assets exceed bound')
    # A private snapshot prevents candidate files being swapped between their
    # byte check and the existing upload CLI. No ISO/closure re-export occurs.
    require(shutil.disk_usage(directory.parent).free>=total+len(raw)+256*1024**2,'Insufficient private asset snapshot headroom')
    if assets is None:assets=publication.module('native_assets','MAESTRO_PUBLICATION_ASSETS_SOURCE','../../../release/publication/_source/publication-assets.py')
    execute=execute or native.operations.run
    policy_digest=native.file_hash(policy_path)
    def authorize():publication.fresh(bundle,policy_path,policy_digest)
    authorize()
    with tempfile.TemporaryDirectory(prefix='.native-release-writer-',dir=directory.parent) as temporary:
        root=Path(temporary);frozen=root/'release';frozen.mkdir()
        for name,row in records.items():
            with os.fdopen(os.open(directory/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as source,(frozen/name).open('xb') as out:
                info=os.fstat(source.fileno());require(stat.S_ISREG(info.st_mode) and info.st_size==row['size'],'Release asset changed before snapshot')
                remaining=row['size']
                while remaining:
                    block=source.read(min(1024**2,remaining));require(block,'Release asset shrank')
                    remaining-=len(block);out.write(block)
                require(not source.read(1),'Release asset grew')
            require(native.file_hash(frozen/name)==row['sha256'],'Staged release asset digest differs')
        # Retain the exact bounded receipt, not a regenerated equivalent. Its
        # signature is independently required before any public mutation.
        public_receipt=frozen/manifest.name
        public_receipt.write_bytes(raw)
        receipt_digest=hashlib.sha256(raw).hexdigest()
        (verify_receipt or receipt_attestation)(native,public_receipt,policy_revision)
        require(native.file_hash(public_receipt)==receipt_digest,'Receipt changed during signature verification')
        joined=hashlib.sha256()
        for name in parts:
            with (frozen/name).open('rb') as source:
                while block:=source.read(1024**2):joined.update(block)
        require(joined.hexdigest()==digest and (frozen/(filename+'.sha256')).read_text()==digest+'  '+filename+'\n','Split installer bytes/checksum differ from boot proof')
        sbom_hashes={}
        for kind in ('spdx','cdx'):
            name='maestro-'+tag+'.'+kind+'.json.gz'
            require((frozen/(name+'.sha256')).read_text()==records[name]['sha256']+'  '+name+'\n','Changed SBOM checksum')
            original=bundle['directory']/('maestro-system.'+kind+'.json');h=hashlib.sha256();length=0
            with gzip.open(frozen/name,'rb') as source:
                while block:=source.read(1024**2):
                    length+=len(block);require(length<=original.stat().st_size,'Expanded SBOM exceeds original inventory')
                    h.update(block)
            sbom_hashes[kind]=native.file_hash(original)
            require(length==original.stat().st_size and h.hexdigest()==sbom_hashes[kind],'Compressed SBOM differs from authenticated inventory')
        # Reuse the established native GitHub verifier for both SLSA provenance
        # and the complete SPDX predicate, exact final filename/digest/source.
        candidate=root/'candidate';candidate.mkdir()
        document=bundle['directory']/'maestro-system.spdx.json'
        target=candidate/document.name
        with document.open('rb') as source,target.open('xb') as output:
            remaining=document.stat().st_size
            require(0<remaining<=native.MAX_DOCUMENT,'Bounded original SPDX required')
            while remaining:
                block=source.read(min(1024**2,remaining));require(block,'Original SPDX shrank')
                remaining-=len(block);output.write(block)
            require(not source.read(1),'Original SPDX grew')
        require(native.file_hash(target)==sbom_hashes['spdx'],'Original SPDX changed during verification snapshot')
        execute(['maestro-ci-release-attestations'],check=True,timeout=900,cwd=root,
            env=dict(os.environ,SOURCE_SHA=policy_revision,RELEASE_TAG=tag,RUNNER_TEMP=str(iso.parent.resolve())))
        require(native.file_hash(iso)==digest,'ISO changed during final-name attestation verification')
        authorize()
        require(native.file_hash(public_receipt)==receipt_digest,'Signed receipt changed before publication')
        product=dict(repository=native.REPO,revision=revision,
            assets={**{name:row['sha256'] for name,row in records.items()},manifest.name:receipt_digest})
        result=assets.reconcile(native.REPO,product,frozen,tag,revision,True,authorize)
        authorize()
        return dict(result,authorization=False,sourceRevision=revision,policyRevision=policy_revision,
            isoBytesVerified=True,narBytesVerified=False)
