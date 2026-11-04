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


class ReleaseWorkflowPermissionError(ValueError):
    """Nonsensitive diagnosis preserved by the native CLI's type-only errors."""


def destination(native,tag,revision,policy_revision,*,read_only=False):
    """Bounded read-only discovery; absence is a complete successful listing."""
    require=native.require
    require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag) and
        all(isinstance(s,str) and re.fullmatch(r'[0-9a-f]{40}',s) for s in (revision,policy_revision)),
        'Exact release destination identity required')
    matches=[]
    for page in range(1,11):
        rows=native.api(f'releases?per_page=100&page={page}')
        require(isinstance(rows,list) and len(rows)<=100 and all(isinstance(row,dict) for row in rows),'Bounded complete release listing required')
        matches.extend(row for row in rows if row.get('tag_name')==tag)
        require(len(matches)<=1,'Ambiguous release destination')
        if len(rows)<100:break
    else:raise ValueError('Release discovery exceeds bounded inventory')
    release=matches[0] if matches else None
    if release is not None:
        require(type(release.get('id')) is int and release['id']>0 and release.get('target_commitish')==revision
            and type(release.get('draft')) is bool,'Existing release target differs from product')
    rows=native.api('git/matching-refs/tags/'+tag)
    require(isinstance(rows,list) and len(rows)<1000 and all(isinstance(row,dict) for row in rows),'Bounded tag listing required')
    refs=[row for row in rows if row.get('ref')=='refs/tags/'+tag]
    require(len(refs)<=1,'Ambiguous exact release tag')
    if refs:
        obj=refs[0].get('object',{})
        for _ in range(5):
            require(isinstance(obj,dict) and isinstance(obj.get('sha'),str) and re.fullmatch(r'[0-9a-f]{40}',obj['sha']),'Invalid exact tag object')
            if obj.get('type')=='commit':break
            require(obj.get('type')=='tag','Unsupported exact release tag object')
            record=native.api('git/tags/'+obj['sha'])
            require(isinstance(record,dict),'Malformed annotated tag response')
            obj=record.get('object',{})
        else:raise ValueError('Tag nesting exceeds bound')
        require(obj['sha']==revision,'Existing release tag differs from product')
    # Read-only preflight cannot prove that a draft is absent. A visible exact
    # tag may be resumable; only the writer's contents-write view can decide.
    unseen_draft=read_only and release is None and bool(refs)
    if (release is None or not refs) and not unseen_draft:
        repo=native.api('')
        require(isinstance(repo,dict) and repo.get('id')==1127149753 and repo.get('full_name')==native.REPO and repo.get('default_branch')=='main',
            'Exact main-default release repository required')
        if revision!=policy_revision:
            trees=[]
            for source in (revision,policy_revision):
                rows=native.api('contents/.github?ref='+source)
                require(isinstance(rows,list) and 0<len(rows)<1000 and all(isinstance(row,dict) for row in rows),'Complete workflow tree metadata required')
                found=[row for row in rows if row.get('name')=='workflows' and row.get('path')=='.github/workflows']
                require(len(found)==1 and found[0].get('type')=='dir' and isinstance(found[0].get('sha'),str)
                    and re.fullmatch(r'[0-9a-f]{40}',found[0]['sha']),'Exact workflow Git tree required')
                trees.append(found[0]['sha'])
            if trees[0]!=trees[1]:
                raise ReleaseWorkflowPermissionError('GitHub token cannot create this older-source release: workflows differ from current main')
    return dict(release=release,tagExists=bool(refs),requiresWritableReadback=unseen_draft)


def read_receipt(native,row):
    """Read only one fixed, bounded GitHub asset; never infer absence on failure."""
    import resource
    native.require(isinstance(row,dict) and type(row.get('id')) is int and row['id']>0 and type(row.get('size')) is int
        and 0<row['size']<=1024**2 and row.get('name')=='native-release-staging.json'
        and row.get('state')=='uploaded' and isinstance(row.get('digest'),str)
        and re.fullmatch(r'sha256:[0-9a-f]{64}',row['digest']),'Exact bounded stored receipt required')
    with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
        def cap():resource.setrlimit(resource.RLIMIT_FSIZE,(1024**2,1024**2))
        native.operations.run(['gh','api','--method','GET','-H','Accept: application/octet-stream',
            f'repos/{native.REPO}/releases/assets/{row["id"]}'],stdout=out,stderr=err,check=True,timeout=90,preexec_fn=cap)
        native.require(out.tell()==row['size'] and err.tell()<=1024**2,'Stored receipt transfer differs from descriptor')
        out.seek(0);raw=out.read(1024**2+1)
    native.require('sha256:'+hashlib.sha256(raw).hexdigest()==row['digest'],'Stored receipt bytes changed')
    return raw


def retained_receipt(publication,release,current,records,path,policy_revision,verify,reader):
    """Keep original immutable provenance; ignore its historical risk verdict."""
    native=publication.native;require=native.require
    if release is None:return False
    assets=release.get('assets')
    require(isinstance(assets,list) and len(assets)<=25 and all(isinstance(row,dict) for row in assets),'Bounded existing release assets required')
    named=[row for row in assets if row.get('name')==path.name]
    require(len(named)<=1,'Ambiguous stored release receipt')
    if not named:return False
    row=named[0];raw=reader(native,row)
    require(type(raw) is bytes and 0<len(raw)<=1024**2 and row.get('size')==len(raw)
        and row.get('digest')=='sha256:'+hashlib.sha256(raw).hexdigest(),'Stored receipt differs from published descriptor')
    old=publication.risk.parse(raw)
    require(isinstance(old,dict) and all(old.get(key)==current.get(key) for key in
        ('schemaVersion','status','authorization','publicationReady','sourceRevision','sourceRun','sourceAttempt','mediaProducer','version','tag','isoSha256','isoBytesVerified','narBytesVerified','assets'))
        and type(old.get('sourceRun')) is int and type(old.get('sourceAttempt')) is int
        and type(old.get('schemaVersion')) is int and old.get('authorization') is False
        and old.get('publicationReady') is False and old.get('isoBytesVerified') is True
        and old.get('narBytesVerified') is False and old.get('assets')==records,
        'Stored receipt differs from current independently verified immutable product')
    require(all(isinstance(row,dict) and type(row.get('size')) is int for row in old['assets'].values()),'Malformed stored asset descriptors')
    media=old.get('mediaProducer',{})
    require(isinstance(media,dict) and all(type(media.get(k)) is int for k in ('runId','runAttempt')),'Stored media producer differs')
    signer=old.get('policyRevision',old['sourceRevision'])
    require(isinstance(signer,str) and re.fullmatch(r'[0-9a-f]{40}',signer),'Exact original receipt signer required')
    path.write_bytes(raw)
    verify(native,path,signer)
    require(native.file_hash(path)==hashlib.sha256(raw).hexdigest(),'Stored signed receipt changed during verification')
    native.require_ancestor(signer,policy_revision)
    return True


def publish(bundle,directory,iso,policy_path,*,publication=None,assets=None,execute=None,verify_receipt=None,receipt_reader=None):
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
    require(shutil.disk_usage(directory.parent).free>=total+3*1024**2+256*1024**2,'Insufficient private asset snapshot headroom')
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
        existing=destination(native,tag,revision,policy_revision)['release']
        retained=retained_receipt(publication,existing,receipt,records,public_receipt,policy_revision,
            verify_receipt or receipt_attestation,receipt_reader or read_receipt)
        if retained:receipt_digest=native.file_hash(public_receipt)
        product=dict(repository=native.REPO,revision=revision,
            assets={**{name:row['sha256'] for name,row in records.items()},manifest.name:receipt_digest})
        result=assets.reconcile(native.REPO,product,frozen,tag,revision,True,authorize)
        authorize()
        return dict(result,authorization=False,sourceRevision=revision,policyRevision=policy_revision,
            isoBytesVerified=True,narBytesVerified=False,retainedReceipt=retained)
