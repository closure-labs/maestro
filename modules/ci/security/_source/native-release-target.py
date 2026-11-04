#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive signed release-receipt locator; never inventory or risk admission."""
import importlib.util
import os
from pathlib import Path
import re
import stat
import tempfile

spec=importlib.util.spec_from_file_location('official_native_prepare',os.environ.get(
    'MAESTRO_NATIVE_PREPARE_SOURCE',Path(__file__).with_name('native-prepare.py')))
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
require=native.require
NAME='native-release-staging.json'
SIGNER='.github/workflows/release.yml'
CAP=1024**2


def resolve(path,tag,publication_revision,policy_revision,*,api=native.api,verify=native.response):
    """Return a scheduling tuple only after exact receipt signature/release binding.

    The caller must still authenticate original CI, full inventory and boot, then
    restore/check real NAR bytes and scan with fresh databases. The release writer
    must first retain/attest its existing staging receipt; no legacy fallback.
    """
    require(isinstance(tag,str) and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag),'Exact version tag required')
    require(all(isinstance(s,str) and re.fullmatch(r'[0-9a-f]{40}',s)
                for s in (publication_revision,policy_revision)),'Exact signer/current policy revisions required')
    require(api('git/ref/heads/main')['object']['sha']==policy_revision,'Current main changed')
    release=api('releases/tags/'+tag)
    require(type(release.get('id')) is int and release['id']>0 and release.get('tag_name')==tag
            and release.get('draft') is False and release.get('prerelease') is False,'Exact published stable release required')
    ref=api('git/ref/tags/'+tag).get('object',{})
    require(ref.get('type')=='commit' and isinstance(ref.get('sha'),str)
            and re.fullmatch(r'[0-9a-f]{40}',ref['sha']),'Exact immutable product commit required')
    source=Path(path)
    # Freeze a bounded regular file before both signature and content validation.
    with tempfile.TemporaryDirectory(prefix='maestro-official-target-') as temp:
        frozen=Path(temp)/NAME
        with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as incoming:
            info=os.fstat(incoming.fileno());require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=CAP,'Bounded regular receipt required')
            raw=incoming.read(CAP+1);require(len(raw)==info.st_size,'Receipt changed during read')
        frozen.write_bytes(raw)
        result=verify('attestation','verify',str(frozen),'--repo',native.REPO,
            '--signer-workflow',native.REPO+'/'+SIGNER,'--source-ref','refs/heads/main',
            '--source-digest',publication_revision,'--signer-digest',publication_revision,
            '--deny-self-hosted-runners','--predicate-type','https://slsa.dev/provenance/v1','--format','json')
        digest=native.file_hash(frozen)
        require(isinstance(result,list) and any(isinstance(row,dict) and
            isinstance(row.get('verificationResult'),dict) and
            isinstance(row['verificationResult'].get('statement'),dict) and
            row['verificationResult']['statement'].get('predicateType')=='https://slsa.dev/provenance/v1' and
            any(isinstance(s,dict) and s.get('name')==NAME and s.get('digest',{}).get('sha256')==digest
                for s in row['verificationResult']['statement'].get('subject',[])) for row in result),
            'Verified exact release-receipt subject required')
        receipt=native.load_json(frozen)
    require(receipt.get('schemaVersion')==1 and type(receipt['schemaVersion']) is int
            and receipt.get('status')=='staged-native-release-assets'
            and receipt.get('authorization') is False and receipt.get('publicationReady') is False
            and receipt.get('tag')==tag and receipt.get('version')==tag[1:]
            and receipt.get('sourceRevision')==ref['sha'] and receipt.get('policyRevision',ref['sha'])==publication_revision
            and receipt.get('isoBytesVerified') is True and receipt.get('narBytesVerified') is False,
            'Receipt differs from exact native release context')
    for name in ('sourceRun','sourceAttempt'):
        require(type(receipt.get(name)) is int and receipt[name]>0,'Exact original producer tuple required')
    media=receipt.get('mediaProducer',{})
    require(isinstance(media,dict) and set(media)=={'runId','runAttempt','revision'}
            and all(type(media[k]) is int and media[k]>0 for k in ('runId','runAttempt'))
            and isinstance(media.get('revision'),str) and re.fullmatch(r'[0-9a-f]{40}',media['revision']),
            'Complete original media producer required')
    require(isinstance(receipt.get('isoSha256'),str) and re.fullmatch(r'[0-9a-f]{64}',receipt['isoSha256']),
            'Exact shipped ISO digest required')
    assets=release.get('assets');require(isinstance(assets,list) and len(assets)<=100,'Bounded release asset inventory required')
    matches=[a for a in assets if isinstance(a,dict) and a.get('name')==NAME]
    require(len(matches)==1 and type(matches[0].get('id')) is int and matches[0]['id']>0
            and matches[0].get('state')=='uploaded' and matches[0].get('size')==len(raw)
            and type(matches[0].get('size')) is int and matches[0].get('digest')=='sha256:'+digest,
            'Receipt is not the exact published release asset')
    records=receipt.get('assets')
    require(isinstance(records,dict) and 0<len(records)<=24 and NAME not in records,
            'Complete signed payload asset inventory required')
    remote={}
    for asset in assets:
        require(isinstance(asset,dict) and isinstance(asset.get('name'),str) and asset['name'] not in remote,
                'Duplicate or malformed published asset')
        remote[asset['name']]=asset
    require(set(remote)==set(records)|{NAME},'Published assets differ from signed complete release inventory')
    for name,record in records.items():
        require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_.+-]+',name)
                and isinstance(record,dict) and set(record)=={'sha256','size'}
                and isinstance(record.get('sha256'),str) and re.fullmatch(r'[0-9a-f]{64}',record['sha256'])
                and type(record.get('size')) is int and 0<record['size']<2147483648,
                'Invalid bounded signed payload descriptor')
        actual=remote[name]
        require(type(actual.get('id')) is int and actual['id']>0 and actual.get('state')=='uploaded'
                and type(actual.get('size')) is int and actual['size']==record['size']
                and actual.get('digest')=='sha256:'+record['sha256'],
                'Published payload descriptor differs from signed release bytes')
    for revision in {ref['sha'],publication_revision}:
        if revision!=policy_revision:
            relation=api('compare/'+revision+'...'+policy_revision+'?per_page=1')
            require(relation.get('status')=='ahead' and relation.get('base_commit',{}).get('sha')==revision
                    and relation.get('merge_base_commit',{}).get('sha')==revision,'Product/signer is not an ancestor of current policy')
    require(api('git/ref/heads/main')['object']['sha']==policy_revision
            and api('git/ref/tags/'+tag).get('object')==ref,'Main or release tag changed during selection')
    return dict(runId=receipt['sourceRun'],runAttempt=receipt['sourceAttempt'],revision=ref['sha'],
        mediaProducer=media,isoSha256=receipt['isoSha256'],releaseId=release['id'],tag=tag,
        receiptSha256=digest,authorization=False,publicationReady=False,inventoryVerified=False,
        narBytesVerified=False,isoBytesVerified=False,findingsAccepted=False)


def fetch(tag,publication_revision,policy_revision,*,api=native.api,verify=native.response,execute=native.operations.run):
    """Download only the exact bounded public receipt; no ISO/closure payload."""
    import resource
    require(isinstance(tag,str) and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag),'Exact version tag required')
    require(all(isinstance(s,str) and re.fullmatch(r'[0-9a-f]{40}',s) for s in (publication_revision,policy_revision)),
            'Exact signer/current policy revisions required')
    release=api('releases/tags/'+tag)
    assets=release.get('assets');require(isinstance(assets,list) and len(assets)<=100,'Bounded release asset inventory required')
    rows=[a for a in assets if isinstance(a,dict) and a.get('name')==NAME]
    require(len(rows)==1,'One exact published staging receipt required')
    row=rows[0]
    require(type(row.get('id')) is int and row['id']>0 and type(row.get('size')) is int
            and 0<row['size']<=CAP and row.get('state')=='uploaded'
            and isinstance(row.get('digest'),str) and re.fullmatch(r'sha256:[0-9a-f]{64}',row['digest']),
            'Bounded exact release receipt descriptor required')
    with tempfile.TemporaryDirectory(prefix='maestro-official-receipt-') as temp:
        path=Path(temp)/NAME
        def cap():resource.setrlimit(resource.RLIMIT_FSIZE,(CAP,CAP))
        with path.open('xb') as out,tempfile.TemporaryFile() as err:
            execute(['gh','api','--method','GET','-H','Accept: application/octet-stream',
                     f'repos/{native.REPO}/releases/assets/{row["id"]}'],stdout=out,stderr=err,
                    check=True,timeout=90,preexec_fn=cap)
            require(out.tell()==row['size'] and err.tell()<=CAP,'Receipt transfer differs from bounded descriptor')
        require('sha256:'+native.file_hash(path)==row['digest'],'Downloaded receipt digest changed')
        result=resolve(path,tag,publication_revision,policy_revision,api=api,verify=verify)
        require(result['releaseId']==release.get('id'),'Release changed during receipt transfer')
        return result
