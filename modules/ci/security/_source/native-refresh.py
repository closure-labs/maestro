#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive native refresh producer; retain original inputs, emit fresh health only."""
import datetime as dt
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shutil
import tempfile
import sys
import subprocess


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


native = module('refresh_prepare', os.environ.get('MAESTRO_NATIVE_PREPARE_SOURCE', Path(__file__).with_name('native-prepare.py')))
health = module('refresh_health', os.environ.get('MAESTRO_SECURITY_NATIVE_CHECK_SOURCE', Path(__file__).with_name('security-native-check.py')))
require = native.require
INPUTS = ('maestro-system.cdx.json', 'xen-orchestra-supply.cdx.json', 'Cargo.lock')
REPORTS = {'grype-version.json','cargo-audit-version.txt','scanner-check.grype.json',
    'maestro-system.grype.json','grype-database.json','cargo-audit.json','rustsec-database.json',
    'findings.json','grype-findings.json','critical-applicability.json','effective-policy.json',
    'inputs.sha256','source-policy.json','security-result.json','new-high-critical.json'}



def select_current_main(api=native.api):
    """One exact protected main producer; metadata schedules verification only."""
    revision=os.environ.get('GITHUB_SHA','')
    require(os.environ.get('GITHUB_REPOSITORY')==native.REPO
        and os.environ.get('GITHUB_REF')=='refs/heads/main'
        and os.environ.get('GITHUB_EVENT_NAME')=='schedule'
        and re.fullmatch(r'[0-9a-f]{40}',revision), 'Native current-main refresh requires a protected schedule')
    branch=api('branches/main')
    require(branch.get('protected') is True and branch.get('commit',{}).get('sha')==revision,
            'Refresh policy/main changed before selection')
    workflow=api('actions/workflows/ci.yml')
    require(type(workflow.get('id')) is int and workflow['id']>0
        and workflow.get('path')==native.WORKFLOW and workflow.get('state')=='active','Exact active CI workflow required')
    rows=api('actions/workflows/ci.yml/runs?branch=main&event=push&status=success&head_sha='+revision+'&per_page=100')
    runs=rows.get('workflow_runs')
    require(isinstance(runs,list) and type(rows.get('total_count')) is int
        and rows['total_count']==len(runs) and len(runs)<100
        and all(isinstance(r,dict) for r in runs),'Bounded complete current-main CI inventory required')
    candidates=[r for r in runs if r.get('head_sha')==revision]
    require(len(candidates)==1,'One successful exact-current-main CI producer required; no historical fallback')
    run=candidates[0];identity=run.get('id');attempt=run.get('run_attempt')
    require(type(identity) is int and identity>0 and type(attempt) is int and attempt>0
        and run.get('workflow_id')==workflow['id'] and run.get('path')==native.WORKFLOW
        and run.get('head_branch')=='main' and run.get('event')=='push'
        and run.get('status')=='completed' and run.get('conclusion')=='success'
        and all((run.get(key) or {}).get('full_name')==native.REPO
                and (run.get(key) or {}).get('id')==1127149753
                for key in ('repository','head_repository')), 'Untrusted scheduled CI producer')
    # The actual consumer verifies this exact attempt, all artifacts and signatures.
    native.trusted_run(identity,attempt,revision)
    require(api('git/ref/heads/main')['object']['sha']==revision,'Main changed during refresh selection')
    return identity,attempt,revision


def official_product(tag,signer,policy):
    require(os.environ.get('GITHUB_REPOSITORY')==native.REPO
        and os.environ.get('GITHUB_REF')=='refs/heads/main'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch'
        and policy==os.environ.get('GITHUB_SHA') and isinstance(signer,str)
        and re.fullmatch(r'[0-9a-f]{40}',signer),'Explicit protected official refresh required')
    locator=module('official_refresh_target',os.environ.get('MAESTRO_NATIVE_RELEASE_TARGET_SOURCE',Path(__file__).with_name('native-release-target.py')))
    return locator.fetch(tag,signer,policy)


def official_binding(bundle,target):
    receipt=bundle['receipt']
    media=receipt.get('bootOrigin') or dict(runId=receipt['runId'],runAttempt=receipt['runAttempt'],revision=receipt['sourceRevision'])
    require((receipt['runId'],receipt['runAttempt'],receipt['sourceRevision'])==
        (target['runId'],target['runAttempt'],target['revision']) and media==target['mediaProducer']
        and bundle['result']['boot']['isoSha256']==target['isoSha256'],
        'Verified official inventory/media differs from published native release')


def scheduled_official(policy,api=native.api):
    require(os.environ.get('GITHUB_REPOSITORY')==native.REPO and os.environ.get('GITHUB_REF')=='refs/heads/main'
        and os.environ.get('GITHUB_EVENT_NAME')=='schedule' and os.environ.get('GITHUB_SHA')==policy
,'Scheduled official refresh requires protected main')
    latest=api('releases/latest')
    require(type(latest.get('id')) is int and latest['id']>0 and latest.get('draft') is False
        and latest.get('prerelease') is False and isinstance(latest.get('tag_name'),str)
        and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',latest['tag_name']),'One stable official release required')
    locator=module('scheduled_official_target',os.environ.get('MAESTRO_NATIVE_RELEASE_TARGET_SOURCE',Path(__file__).with_name('native-release-target.py')))
    result=locator.fetch(latest['tag_name'],None,policy,discover_signer=True)
    require(result['releaseId']==latest['id'],'Official release changed during selection')
    return result


def official_current(target,api=native.api):
    latest=api('releases/latest')
    require(latest.get('id')==target['releaseId'] and latest.get('tag_name')==target['tag']
        and latest.get('draft') is False and latest.get('prerelease') is False,'Official release changed during refresh')
    require(api('git/ref/heads/main')['object']['sha']==os.environ['GITHUB_SHA'],'Main changed during official refresh')


def reuse_same_product(target,raw):
    if not raw:return False
    require(len(raw.encode())<=4096,'Bounded same-run product metadata required')
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'Duplicate same-run product metadata');result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'Nonfinite same-run product metadata'))
    require(isinstance(value,dict) and value.get('healthRunId')==int(os.environ['GITHUB_RUN_ID'])
        and type(value.get('healthRunId')) is int and value.get('healthRunAttempt')==int(os.environ['GITHUB_RUN_ATTEMPT'])
        and type(value.get('healthRunAttempt')) is int and value.get('policyRevision')==os.environ['GITHUB_SHA'],
        'Health reuse must come from the successful upstream job of this invocation')
    expires=native.common.timestamp(value.get('expiresAt'));now=dt.datetime.now(dt.timezone.utc)
    require(now<expires<=now+dt.timedelta(hours=24),'Same-run health expired or overlong')
    for key in ('runId','runAttempt'):require(type(value.get(key)) is int and value[key]>0,'Exact upstream verified product required')
    require(isinstance(value.get('revision'),str) and re.fullmatch(r'[0-9a-f]{40}',value['revision']),'Exact upstream source required')
    return all(value[k]==target[k] for k in ('runId','runAttempt','revision'))


def job_outputs(manifest,scoped=False):
    if not os.environ.get('GITHUB_OUTPUT'):return
    product=dict(manifest['originalProducer'],healthRunId=int(os.environ['GITHUB_RUN_ID']),
        healthRunAttempt=int(os.environ['GITHUB_RUN_ATTEMPT']),policyRevision=os.environ['GITHUB_SHA'],expiresAt=manifest['expiresAt'])
    name=(f"maestro-native-health-{product['runId']}-{product['runAttempt']}-{product['revision']}" if scoped else 'maestro-native-health')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a') as output:
            output.write('verified_product='+json.dumps(product,separators=(',',':'))+'\nhealth_artifact='+name+'\nreused=false\n')


def identities(paths):
    # Only the sixty explicit roots, not another recursive closure inventory.
    def cap():resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024**2, 16 * 1024**2))
    with tempfile.TemporaryFile() as output:
        native.operations.run(['nix', 'path-info', '--json', *sorted(paths)],
                              stdout=output, check=True, timeout=120, preexec_fn=cap)
        require(output.tell() <= 16 * 1024**2, 'Root identity response exceeds bound')
        output.seek(0); data = json.load(output)
    if isinstance(data, list):
        require(len({row['path'] for row in data}) == len(data), 'Duplicate realized root')
        data = {row['path']: row for row in data}
    require(isinstance(data, dict), 'Invalid realized root identity response')
    return {path: value['narHash'] for path, value in data.items()}


def refresh(bundle, output, cfg, transport, restore, query=identities, scan=None, api=native.api, scheduled=False):
    """Called only with a frozen verified_inventory context, never a receipt file."""
    require(bundle.get('inventoryOnly') is True, 'Explicit authenticated inventory purpose required')
    require(native.common.canonical_hash(cfg) == bundle['policyHash'], 'Original scope/freshness policy changed')
    revision = bundle['receipt']['sourceRevision']
    policy_revision = bundle['receipt'].get('policyRevision',revision)
    require(os.environ.get('GITHUB_REPOSITORY') == native.REPO
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and (os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' or
                 (scheduled is True and os.environ.get('GITHUB_EVENT_NAME') == 'schedule'))
            and os.environ.get('GITHUB_SHA') == policy_revision, 'Protected exact-source refresh required')
    run, attempt = int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])
    require(run > 0 and attempt > 0, 'Positive fresh producer identity required')
    source = bundle['directory']
    output = Path(output).absolute()
    require(not output.exists() and output != source and output not in source.parents
            and source not in output.parents, 'New separate output directory required')
    require(set(bundle['inputIdentities']) == set(INPUTS), 'Complete original scanner inputs required')

    def current():
        require(api('git/ref/heads/main')['object']['sha'] == policy_revision, 'Main changed during native refresh')

    current()
    proof_names = (*native.JSON_FILES, *native.DOCUMENTS, 'inputs.sha256', 'Cargo.lock',
                   *(('original-ci-result.json', 'original-boot.log') if bundle['receipt'].get('bootOrigin') else ()))
    def original_proof():
        return {name: dict(sha256=native.file_hash(source / name), size=(source / name).stat().st_size)
                for name in proof_names}
    proof = original_proof()
    roots = {row['storePath']: row['narHash'] for row in bundle['native']['subjects']}
    expected_transport = bundle['scans'].get('transport')
    require(isinstance(expected_transport, dict) and expected_transport, 'Original authenticated transport required')
    print('Native refresh: download original transport once',file=sys.stderr,flush=True)
    directory = transport() # Exactly one lazy download of the original authenticated transport.
    print('Native refresh: restore and verify original root/NAR identities',file=sys.stderr,flush=True)
    restore(directory, expected_transport, [dict(storePath=p, narHash=h) for p, h in roots.items()])
    require(query(roots) == roots, 'Realized original root/NAR identities differ')
    current()
    output.mkdir(mode=0o700)
    try:
        started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        environment = dict(os.environ, SECURITY_INVENTORY=str(source), SECURITY_OUTPUT=str(output),
                           SECURITY_CARGO_LOCK=str(source / 'Cargo.lock'))
        # Existing scanner uses one fresh temporary Grype DB and one fresh RustSec
        # checkout. It revalidates shipped files/npm against the restored NARs.
        print('Native refresh: scan original inventory with fresh databases',file=sys.stderr,flush=True)
        (scan or (lambda env: native.operations.run(['maestro-ci-security-scan'], env=env,
                                                    check=True, timeout=3600)))(environment)
        # Bound retained report files below, not every scanner subprocess file:
        # a global file-size ulimit would also truncate legitimate temporary DBs.
        current()
        print('Native refresh: verify fresh health and immutable input bindings',file=sys.stderr,flush=True)
        files = list(output.iterdir())
        require({'security-result.json','inputs.sha256',*native.PUBLICATION_FILES} <= {p.name for p in files}
                and {p.name for p in files} <= REPORTS, 'Incomplete or unexpected fresh report files')
        require(all(path.is_file() and not path.is_symlink() and path.stat().st_size <= native.MAX_DOCUMENT
                    for path in files) and sum(path.stat().st_size for path in files) <= native.MAX_BUNDLE,
                'Fresh scanner output exceeds regular-file resource bounds')
        with native.bounded_validation():
            fresh = native.load_json(output / 'security-result.json')
            health.check(fresh, cfg)
            native.common.coverage_roots(fresh, cfg['requiredCoverage']['maestro'])
        scanned = native.common.timestamp(fresh['scannedAt'])
        require(scanned >= started, 'Scanner reused a pre-invocation result')
        require(fresh['subjects'] == bundle['native']['subjects']
                and fresh['securityContext'] == bundle['native']['securityContext'],
                'Fresh scan changed original subjects or product context')
        checksums = output / 'inputs.sha256'
        require(checksums.stat().st_size <= 4096, 'Fresh input checksum file exceeds bound')
        observed = {}
        for line in checksums.read_text().splitlines():
            match = re.fullmatch(r'([0-9a-f]{64}) [ *](.+)', line)
            require(match is not None, 'Malformed fresh input checksum')
            name = Path(match[2]).name
            require(name in INPUTS and name not in observed, 'Unexpected or duplicate fresh input')
            observed[name] = match[1]
        require(observed == bundle['inputIdentities']
                and all(native.file_hash(source / name) == digest for name, digest in observed.items()),
                'Fresh scan changed original inventory or lockfile')
        expected = fresh.get('evidence', {})
        require(expected.get('inputHashes') == dict(sha256=native.file_hash(checksums), size=checksums.stat().st_size)
                and expected.get('inventory') == dict(sha256=observed['maestro-system.cdx.json'],
                    size=(source / 'maestro-system.cdx.json').stat().st_size), 'Unbound fresh scanner inputs')
        # No old transport, SBOM, native report or CI result is copied to output.
        # A future consumer must authenticate both original CI and this distinct
        # health producer; this local manifest grants no admission or publication.
        require(original_proof() == proof, 'Original frozen evidence changed during scan')
        manifest = dict(schemaVersion=1, kind='native-refreshed-health', repository=native.REPO,
            sourceRevision=revision, producer=dict(workflow='.github/workflows/security.yml',
                runId=run, runAttempt=attempt, revision=policy_revision),
            originalProducer=dict(runId=bundle['receipt']['runId'], runAttempt=bundle['receipt']['runAttempt'], revision=revision),
            originalProof=proof, originalTransport=expected_transport,
            securityResult=dict(sha256=native.file_hash(output / 'security-result.json'), size=(output / 'security-result.json').stat().st_size),
            scannedAt=fresh['scannedAt'], expiresAt=(scanned + dt.timedelta(hours=min(24, cfg['maxEvidenceAgeHours']))).isoformat(),
            authorization=False, publicationReady=False)
        if 'policyRevision' in bundle['receipt']:manifest.update(schemaVersion=2,policyRevision=policy_revision)
        current()
        encoded=json.dumps(manifest,sort_keys=True)+'\n'
        require(len(encoded.encode())<=native.MAX_JSON and sum(path.stat().st_size for path in files)+len(encoded.encode())<=native.MAX_BUNDLE,
                'Fresh manifest/report resource bound exceeded')
        (output / 'native-health.json').write_text(encoded)
        print('Native refresh: fresh report ready for separate attestation; no publication',file=sys.stderr,flush=True)
        return manifest
    except BaseException:
        shutil.rmtree(output)
        raise


def run():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--select-official-release',action='store_true',help='Protected scheduled shipped-product refresh')
    cli.add_argument('--official-tag',help='Explicit stable native release; requires its exact signed public receipt')
    cli.add_argument('--official-publication-revision',help='Exact reviewed release signer revision')
    cli.add_argument('--select-current-main',action='store_true',help='Scheduled exact protected-main CI selection; never select historical decisions')
    cli.add_argument('--run',type=int);cli.add_argument('--attempt',type=int)
    cli.add_argument('--revision');cli.add_argument('--output',type=Path,required=True)
    cli.add_argument('--policy-revision',help='Explicit current scanner/policy source; immutable product source is unchanged')
    cli.add_argument('--boot-origin-run',type=int);cli.add_argument('--boot-origin-attempt',type=int)
    cli.add_argument('--boot-origin-revision');args=cli.parse_args()
    require(args.policy_revision is None or re.fullmatch(r'[0-9a-f]{40}',args.policy_revision),'Exact policy revision required')
    origin=(args.boot_origin_run,args.boot_origin_attempt,args.boot_origin_revision)
    require(all(v is None for v in origin) or all(v is not None for v in origin),'Complete original boot identity required')
    origin=None if all(v is None for v in origin) else origin
    target=None
    require((args.official_tag is None)==(args.official_publication_revision is None),'Complete official tag/signer identity required')
    require(not args.select_official_release or (args.official_tag is None and not args.select_current_main
        and all(v is None for v in (args.run,args.attempt,args.revision,origin))),'Conflicting scheduled/explicit refresh identities')
    if args.select_official_release:
        target=scheduled_official(args.policy_revision)
        args.run,args.attempt,args.revision=(target[k] for k in ('runId','runAttempt','revision'))
        if reuse_same_product(target,os.environ.get('NATIVE_REFRESH_REUSE_PRODUCT','')):
            official_current(target)
            print('Native refresh: reuse this successful invocation health; no second restore or scan',file=sys.stderr,flush=True)
            if os.environ.get('GITHUB_OUTPUT'):
                with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('reused=true\n')
            print(json.dumps(dict(status='same-invocation-product-health-reused',authorization=False,publicationReady=False)))
            return
    elif args.official_tag is not None:
        require(not args.select_current_main and all(v is None for v in (args.run,args.attempt,args.revision,origin)),
            'Conflicting official/current/manual refresh identities')
        print('Native refresh: resolve exact signed official release receipt',file=sys.stderr,flush=True)
        target=official_product(args.official_tag,args.official_publication_revision,args.policy_revision)
        args.run,args.attempt,args.revision=(target[k] for k in ('runId','runAttempt','revision'))
    elif args.select_current_main:
        require(all(v is None for v in (args.run,args.attempt,args.revision,origin)), 'Conflicting automatic/manual refresh identities')
        require(args.policy_revision==os.environ.get('GITHUB_SHA'), 'Scheduled refresh requires exact current policy')
        args.run,args.attempt,args.revision=select_current_main()
    else:
        require(type(args.run) is int and args.run>0 and type(args.attempt) is int and args.attempt>0
            and isinstance(args.revision,str) and re.fullmatch(r'[0-9a-f]{40}',args.revision), 'Exact explicit refresh producer required')
    stage=module('refresh_stage',os.environ.get('MAESTRO_NATIVE_STAGE_SOURCE',Path(__file__).with_name('native-stage.py')))
    distribution=module('refresh_distribution',os.environ.get('MAESTRO_DISTRIBUTION_CACHE_SOURCE',Path(__file__).parents[2]/'graph/_source/distribution-cache.py'))
    policy=Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY'])
    with tempfile.TemporaryDirectory(prefix='maestro-refresh-',dir=os.environ.get('RUNNER_TEMP')) as temp:
        root=Path(temp);directory=root/'original'
        print('Native refresh: stage exact original CI evidence',file=sys.stderr,flush=True)
        origin=stage.stage_refresh(directory,args.run,args.attempt,args.revision,origin,discover_origin=args.select_current_main or target is not None)
        print('Native refresh: authenticate original CI and boot proof',file=sys.stderr,flush=True)
        with native.verified_inventory(directory,args.run,args.attempt,args.revision,policy,origin,policy_revision=args.policy_revision) as bundle:
            if target is not None:official_binding(bundle,target)
            result=refresh(bundle,args.output,native.common.config(policy),
                lambda:stage.transport(args.run,args.revision,root/'closure'),distribution.restore,
                scheduled=(args.select_current_main or args.select_official_release) and os.environ.get('GITHUB_EVENT_NAME')=='schedule')
            if args.select_official_release:
                try:official_current(target)
                except Exception:
                    shutil.rmtree(args.output);raise
            job_outputs(result,scoped=args.select_official_release)
    print(json.dumps(dict(status='fresh-health-produced',authorization=False,publicationReady=False,
        sourceRevision=result['sourceRevision'],originalProducer=result['originalProducer'],producer=result['producer']),sort_keys=True))


def main():
    # Include receipt/producer selection in the existing whole-command deadline.
    with native.operations.budget(2400):return run()


if __name__=='__main__':
    try:main()
    except (ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError,MemoryError,RecursionError) as error:
        print('Native refresh blocked: '+type(error).__name__,file=sys.stderr);sys.exit(2)
