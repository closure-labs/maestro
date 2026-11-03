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


def refresh(bundle, output, cfg, transport, restore, query=identities, scan=None, api=native.api):
    """Called only with a frozen verified_inventory context, never a receipt file."""
    require(bundle.get('inventoryOnly') is True, 'Explicit authenticated inventory purpose required')
    require(native.common.canonical_hash(cfg) == bundle['policyHash'], 'Original scope/freshness policy changed')
    revision = bundle['receipt']['sourceRevision']
    require(os.environ.get('GITHUB_REPOSITORY') == native.REPO
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_SHA') == revision, 'Protected exact-source refresh required')
    run, attempt = int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])
    require(run > 0 and attempt > 0, 'Positive fresh producer identity required')
    source = bundle['directory']
    output = Path(output).absolute()
    require(not output.exists() and output != source and output not in source.parents
            and source not in output.parents, 'New separate output directory required')
    require(set(bundle['inputIdentities']) == set(INPUTS), 'Complete original scanner inputs required')

    def current():
        require(api('git/ref/heads/main')['object']['sha'] == revision, 'Main changed during native refresh')

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
    directory = transport() # Exactly one lazy download of the original authenticated transport.
    restore(directory, expected_transport, [dict(storePath=p, narHash=h) for p, h in roots.items()])
    require(query(roots) == roots, 'Realized original root/NAR identities differ')
    current()
    output.mkdir(mode=0o700)
    try:
        started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        environment = dict(os.environ, SECURITY_INVENTORY=str(source), SECURITY_OUTPUT=str(output),
                           SECURITY_CARGO_LOCK=str(source / 'Cargo.lock'))
        def scan_cap():resource.setrlimit(resource.RLIMIT_FSIZE, (native.MAX_DOCUMENT, native.MAX_DOCUMENT))
        # Existing scanner uses one fresh temporary Grype DB and one fresh RustSec
        # checkout. It revalidates shipped files/npm against the restored NARs.
        (scan or (lambda env: native.operations.run(['maestro-ci-security-scan'], env=env,
                                                    check=True, timeout=3600, preexec_fn=scan_cap)))(environment)
        current()
        files = list(output.iterdir())
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
                runId=run, runAttempt=attempt, revision=revision),
            originalProducer=dict(runId=bundle['receipt']['runId'], runAttempt=bundle['receipt']['runAttempt'], revision=revision),
            originalProof=proof, originalTransport=expected_transport,
            securityResult=dict(sha256=native.file_hash(output / 'security-result.json'), size=(output / 'security-result.json').stat().st_size),
            scannedAt=fresh['scannedAt'], expiresAt=(scanned + dt.timedelta(hours=min(24, cfg['maxEvidenceAgeHours']))).isoformat(),
            authorization=False, publicationReady=False)
        current()
        (output / 'native-health.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
        return manifest
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--run',type=int,required=True);cli.add_argument('--attempt',type=int,required=True)
    cli.add_argument('--revision',required=True);cli.add_argument('--output',type=Path,required=True)
    cli.add_argument('--boot-origin-run',type=int);cli.add_argument('--boot-origin-attempt',type=int)
    cli.add_argument('--boot-origin-revision');args=cli.parse_args()
    origin=(args.boot_origin_run,args.boot_origin_attempt,args.boot_origin_revision)
    require(all(v is None for v in origin) or all(v is not None for v in origin),'Complete original boot identity required')
    origin=None if all(v is None for v in origin) else origin
    stage=module('refresh_stage',os.environ.get('MAESTRO_NATIVE_STAGE_SOURCE',Path(__file__).with_name('native-stage.py')))
    distribution=module('refresh_distribution',os.environ.get('MAESTRO_DISTRIBUTION_CACHE_SOURCE',Path(__file__).parents[2]/'graph/_source/distribution-cache.py'))
    policy=Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY'])
    with native.operations.budget(2400),tempfile.TemporaryDirectory(prefix='maestro-refresh-',dir=os.environ.get('RUNNER_TEMP')) as temp:
        root=Path(temp);directory=root/'original'
        stage.stage_refresh(directory,args.run,args.attempt,args.revision,origin)
        with native.verified_inventory(directory,args.run,args.attempt,args.revision,policy,origin) as bundle:
            result=refresh(bundle,args.output,native.common.config(policy),
                lambda:stage.transport(args.run,args.revision,root/'closure'),distribution.restore)
    print(json.dumps(dict(status='fresh-health-produced',authorization=False,publicationReady=False,
        sourceRevision=result['sourceRevision'],originalProducer=result['originalProducer'],producer=result['producer']),sort_keys=True))


if __name__=='__main__':
    try:main()
    except (ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError,MemoryError,RecursionError) as error:
        print('Native refresh blocked: '+type(error).__name__,file=sys.stderr);sys.exit(2)
