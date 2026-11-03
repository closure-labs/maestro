#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive fresh-health overlay; original inventory proof never becomes health."""
from contextlib import contextmanager
import datetime as dt
import importlib.util
import os
from pathlib import Path
import stat
import tempfile


def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


refresh=module('health_refresh',os.environ.get('MAESTRO_NATIVE_REFRESH_SOURCE',Path(__file__).with_name('native-refresh.py')))
native=refresh.native
require=native.require
WORKFLOW='.github/workflows/security.yml'
FILES=('native-health.json','security-result.json','inputs.sha256',*native.PUBLICATION_FILES)


def freeze(source, destination, original):
    require(source.is_dir() and not source.is_symlink(),'Regular fresh-health directory required')
    total=sum(p.stat().st_size for p in original.iterdir() if p.is_file())
    for name in FILES:
        cap=native.MAX_REPORT if name=='security-result.json' else 4096 if name=='inputs.sha256' else native.MAX_JSON
        with os.fdopen(os.open(source/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
            info=os.fstat(stream.fileno());total+=info.st_size
            require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=cap and total<=native.MAX_BUNDLE,
                    'Oversized or nonregular aggregate original/fresh evidence')
            copied=0
            with (destination/name).open('xb') as out:
                while block:=stream.read(1024*1024):
                    copied+=len(block);require(copied<=info.st_size,'Fresh evidence grew');out.write(block)
            require(copied==info.st_size,'Fresh evidence shrank')


def trusted(run, attempt, revision):
    require(type(run) is int and run>0 and type(attempt) is int and attempt>0,'Exact positive health producer required')
    record=native.api(f'actions/runs/{run}/attempts/{attempt}')
    require(type(record.get('id')) is int and type(record.get('run_attempt')) is int
            and record.get('id')==run and record.get('run_attempt')==attempt and record.get('head_sha')==revision
            and record.get('head_branch')=='main' and record.get('repository',{}).get('full_name')==native.REPO
            and record.get('head_repository',{}).get('full_name')==native.REPO
            and record.get('path','').split('@')[0]==WORKFLOW
            and record.get('event') == 'workflow_dispatch'
            and record.get('status')=='completed' and record.get('conclusion')=='success','Untrusted fresh-health producer')


def attest(path, revision):
    result=native.response('attestation','verify',str(path),'--repo',native.REPO,
        '--signer-workflow',native.REPO+'/'+WORKFLOW,'--source-ref','refs/heads/main',
        '--source-digest',revision,'--signer-digest',revision,'--deny-self-hosted-runners','--format','json')
    require(isinstance(result,list),'Invalid fresh-health verification result')
    require(any(isinstance(row,dict) and any(isinstance(subject,dict)
        and subject.get('digest',{}).get('sha256')==native.file_hash(path)
        for subject in row.get('verificationResult',{}).get('statement',{}).get('subject',[]))
        for row in result),'Fresh-health attestation lacks exact manifest digest')


@contextmanager
def verified(original, directory, run, attempt, cfg):
    require(original.get('inventoryOnly') is True,'Verified original inventory context required')
    require(native.common.canonical_hash(cfg)==original['policyHash'],'Changed original scope policy')
    revision=original['receipt']['sourceRevision']
    def current():require(native.api('git/ref/heads/main')['object']['sha']==revision,'Main changed during health verification')
    current();trusted(run,attempt,revision)
    with tempfile.TemporaryDirectory(prefix='maestro-native-health-') as temp:
        root=Path(temp);freeze(Path(directory),root,original['directory'])
        attest(root/'native-health.json',revision)
        with native.bounded_validation():
            manifest=native.load_json(root/'native-health.json')
            require(type(manifest.get('schemaVersion')) is int and manifest['schemaVersion']==1
                and manifest.get('kind')=='native-refreshed-health' and manifest.get('repository')==native.REPO
                and manifest.get('sourceRevision')==revision and manifest.get('authorization') is False
                and manifest.get('publicationReady') is False,'Invalid fresh-health manifest')
            require(manifest.get('producer')==dict(workflow=WORKFLOW,runId=run,runAttempt=attempt,revision=revision)
                and manifest.get('originalProducer')==dict(runId=original['receipt']['runId'],runAttempt=original['receipt']['runAttempt'],revision=revision),
                'Fresh health substitutes a producer')
            require(all(type(manifest[key][field]) is int for key in ('producer','originalProducer')
                        for field in ('runId','runAttempt')), 'Noninteger manifest producer identity')
            names=(*native.JSON_FILES,*native.DOCUMENTS,'inputs.sha256','Cargo.lock',
                *(('original-ci-result.json','original-boot.log') if original['receipt'].get('bootOrigin') else ()))
            proof={name:dict(sha256=native.file_hash(original['directory']/name),size=(original['directory']/name).stat().st_size) for name in names}
            require(manifest.get('originalProof')==proof and manifest.get('originalTransport')==original['scans'].get('transport'),
                'Fresh health changes original proof or transport')
            report=root/'security-result.json'
            require(manifest.get('securityResult')==dict(sha256=native.file_hash(report),size=report.stat().st_size),
                    'Fresh report differs from signed manifest')
            fresh=native.load_json(report);normalized=[]
            refresh.health.check(fresh,cfg,normalized.extend)
            native.common.coverage_roots(fresh,cfg['requiredCoverage']['maestro'])
            scanned=native.common.timestamp(fresh['scannedAt']);expires=native.common.timestamp(manifest.get('expiresAt'))
            require(manifest.get('scannedAt')==fresh['scannedAt'] and scanned<expires
                and expires-scanned<=dt.timedelta(hours=min(24,cfg['maxEvidenceAgeHours']))
                and expires>dt.datetime.now(dt.timezone.utc),'Expired or overlong fresh-health interval')
            require(fresh['subjects']==original['native']['subjects'] and fresh['securityContext']==original['native']['securityContext'],
                    'Fresh health changes product subjects or context')
            for name,key in [('findings.json','findings'),('source-policy.json','sourcePolicy'),
                             ('effective-policy.json','effectivePolicy'),('critical-applicability.json','applicability'),('inputs.sha256','inputHashes')]:
                path=root/name
                require(fresh.get('evidence',{}).get(key)==dict(sha256=native.file_hash(path),size=path.stat().st_size),
                        'Fresh finding/policy/input bytes are unbound')
            lines=(root/'inputs.sha256').read_text().splitlines();inputs={}
            for line in lines:
                match=refresh.re.fullmatch(r'([0-9a-f]{64}) [ *](.+)',line)
                require(match is not None,'Malformed fresh-health input checksum')
                name=Path(match[2]).name;require(name in refresh.INPUTS and name not in inputs,'Duplicate or extra fresh-health input')
                inputs[name]=match[1]
            system=original['directory']/'maestro-system.cdx.json'
            require(inputs==original['inputIdentities'] and fresh['evidence'].get('inventory')==dict(sha256=native.file_hash(system),size=system.stat().st_size),
                    'Fresh health changes original scanner inputs')
        current()
        # A scoped in-memory context only; the signed manifest alone is never an
        # admission token. Original CI/product/boot/doc proof remains separate.
        yield dict(original,native=fresh,normalizedFindings=normalized,inventoryOnly=False,
                   policyDirectory=root,healthManifest=manifest)
        current()
