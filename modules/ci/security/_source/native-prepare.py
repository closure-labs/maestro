#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive, read-only preparation of one exact native main evidence bundle."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile

CORE = Path(os.environ.get('MAESTRO_DECISION_CORE', Path(__file__).parents[2] / 'authority/_source/decisions'))
sys.path.insert(0, str(CORE))
import common
import operations
from security_decisions import load_json

REPO = 'closure-labs/maestro'
WORKFLOW = '.github/workflows/ci.yml'
POLICY = 'modules/ci/authority/_source/decision-policy.json'
JSON_FILES = ('product.json', 'scans.json', 'security-result.json', 'ci-result.json', 'inventory-binding.json')
DOCUMENTS = tuple(n + suffix for n in ('maestro-system.spdx.json', 'maestro-system.cdx.json',
    'xen-orchestra-supply.assertion.json', 'xen-orchestra-supply.spdx.json', 'xen-orchestra-supply.cdx.json')
    for suffix in ('', '.sha256'))
MAX_JSON = 16 * 1024**2
MAX_DOCUMENT = 64 * 1024**2
MAX_BUNDLE = 256 * 1024**2
MAX_RESPONSE = 4 * 1024**2
require = common.require


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def response(*args):
    # Fixed GET/verification calls only. Spool rather than buffer CLI output;
    # kernel file limits bound both stdout and stderr, including failed calls.
    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESPONSE, MAX_RESPONSE))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        operations.run(['gh', *args], stdout=out, stderr=err, check=True, timeout=90, preexec_fn=limit)
        require(out.tell() <= MAX_RESPONSE and err.tell() <= MAX_RESPONSE, 'Oversized verification response')
        out.seek(0)
        return json.load(out)


def api(path):
    return response('api', '--method', 'GET', 'repos/' + REPO + '/' + path)


def attest(path, revision):
    verified = response('attestation', 'verify', str(path), '--repo', REPO,
        '--signer-workflow', REPO + '/' + WORKFLOW, '--source-ref', 'refs/heads/main',
        '--source-digest', revision, '--signer-digest', revision,
        '--deny-self-hosted-runners', '--format', 'json')
    expected = file_hash(path)
    require(isinstance(verified, list), 'Invalid attestation response')
    subjects = []
    for row in verified:
        value = row.get('verificationResult') if isinstance(row, dict) else None
        statement = value.get('statement') if isinstance(value, dict) else None
        if isinstance(statement, dict) and isinstance(statement.get('subject'), list):
            subjects.extend(statement['subject'])
    require(any(isinstance(subject, dict) and isinstance(subject.get('digest'), dict)
                and subject['digest'].get('sha256') == expected for subject in subjects),
            'Verified attestation lacks exact subject digest')


def snapshot(directory, destination):
    require(directory.is_dir() and not directory.is_symlink(), 'Regular evidence directory required')
    total = 0
    for name in (*JSON_FILES, *DOCUMENTS):
        source = directory / name
        with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            info = os.fstat(stream.fileno())
            cap = MAX_JSON if name in JSON_FILES else MAX_DOCUMENT
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= cap, 'Invalid or oversized evidence file')
            total += info.st_size
            require(total <= MAX_BUNDLE, 'Oversized evidence bundle')
            with (destination / name).open('xb') as out:
                copied = 0
                while block := stream.read(1024 * 1024):
                    copied += len(block)
                    require(copied <= info.st_size, 'Evidence grew during snapshot')
                    out.write(block)
            require(copied == info.st_size, 'Evidence shrank during snapshot')


def prepare(directory, run_id, attempt, revision, policy_path):
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0
            and re.fullmatch(r'[0-9a-f]{40}', revision), 'Exact native producer inputs required')
    cfg = common.config(policy_path)
    require(cfg['repository'] == REPO and cfg['profiles'] == ['maestro'], 'Unsupported native profile contract')
    require(api('git/ref/heads/main')['object']['sha'] == revision, 'Selected source is not current main')
    remote = api('contents/' + POLICY + '?ref=' + revision)
    require(remote.get('encoding') == 'base64' and remote.get('size', MAX_JSON + 1) <= MAX_JSON,
            'Bounded protected policy required')
    require(common.canonical_hash(json.loads(base64.b64decode(remote['content']))) == common.canonical_hash(cfg),
            'Local policy differs from protected source')
    run = api(f'actions/runs/{run_id}/attempts/{attempt}')
    require(run.get('id') == run_id and run.get('run_attempt') == attempt and run.get('head_sha') == revision
            and type(run.get('id')) is int and type(run.get('run_attempt')) is int
            and run.get('head_branch') == 'main' and run.get('repository', {}).get('full_name') == REPO
            and run.get('head_repository', {}).get('full_name') == REPO
            and run.get('path', '').split('@')[0] == WORKFLOW and run.get('event') in ('push', 'workflow_dispatch')
            and run.get('status') == 'completed' and run.get('conclusion') == 'success', 'Untrusted native run')
    with tempfile.TemporaryDirectory(prefix='maestro-native-prepare-') as temporary:
        root = Path(temporary)
        snapshot(directory, root)
        product, scans, native, result, binding = [load_json(root / name) for name in JSON_FILES]
        for name in ('product.json', 'scans.json', 'ci-result.json'):
            attest(root / name, revision)
        require(type(product.get('schema')) is int and type(scans.get('schema')) is int
                and product.get('schema') == scans.get('schema') == 1
                and product.get('repository') == scans.get('repository') == REPO
                and product.get('revision') == scans.get('revision') == revision, 'Changed native source identity')
        producer = scans.get('producer', {})
        require(producer.get('workflow') == producer.get('signerWorkflow', WORKFLOW) == WORKFLOW
                and type(producer.get('runId')) is int and type(producer.get('runAttempt')) is int
                and producer.get('runId') == run_id and producer.get('runAttempt') == attempt
                and producer.get('revision', revision) == revision
                and scans.get('productProducer') == producer, 'Changed original producer identity')
        origin = dict(GITHUB_REPOSITORY=REPO, GITHUB_SHA=revision, GITHUB_RUN_ID=str(run_id), GITHUB_RUN_ATTEMPT=str(attempt))
        require(type(result.get('schemaVersion')) is int and result['schemaVersion'] == 1, 'Unsupported result schema')
        require(binding.get('schemaVersion') == 2, 'Unsupported inventory schema')
        require(result.get('producer') == binding.get('producer') == origin, 'Changed result producer attempt')
        require(result.get('completeValidationRequired') is True and result.get('jobs') == {
            k: 'success' for k in ('AUDIT_RESULT', 'COMPARISON_RESULT', 'SCAN_RESULT', 'QUALIFICATION_RESULT')},
            'Missing complete validation obligation')
        require(result.get('nativeScanSha256') == file_hash(root / 'security-result.json')
                and scans.get('profiles') == {'maestro': native}, 'Changed native scan bytes')
        require(result.get('inventoryTransferSha256') == file_hash(root / 'inventory-binding.json'), 'Changed inventory binding bytes')
        require(binding.get('phase') == 'inventory' and binding.get('transport') is None
                and set(binding.get('evidenceFiles', {})) == set(DOCUMENTS), 'Incomplete local inventory binding')
        require(all(file_hash(root / n) == h for n, h in binding['evidenceFiles'].items()), 'Changed inventory document bytes')
        require(common.timestamp(scans['scannedAt']) <= common.timestamp(native['scannedAt'])
                and common.timestamp(scans['expiresAt']) > common.dt.datetime.now(common.dt.timezone.utc)
                and common.timestamp(scans['expiresAt']) - common.timestamp(scans['scannedAt']) <= common.dt.timedelta(hours=24),
                'Expired or invalid scan envelope')
        spec = importlib.util.spec_from_file_location('native_check', os.environ.get('MAESTRO_SECURITY_NATIVE_CHECK_SOURCE', Path(__file__).with_name('security-native-check.py')))
        check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
        require(isinstance(native.get('securityContext'), dict) and native['securityContext'].get('schema') == 2, 'Complete installer security context required')
        check.check(native, cfg)
        common.coverage_roots(native, cfg['requiredCoverage']['maestro'])
        require(isinstance(product.get('products'), dict) and isinstance(product.get('roots'), dict), 'Invalid native product roots')
        subjects = native['subjects']
        expected = {v['storePath']: v['narHash'] for v in subjects}
        require(all(set(v) == {'storePath', 'narHash'} for v in product['products'].values())
                and all(set(v) == {'storePath', 'narHash', 'profile'} and v['profile'] == 'maestro'
                        for v in product['roots'].values()), 'Invalid product root profile')
        roots = [*product['products'].values(), *product['roots'].values()]
        require(set(product['products']) == {'maestro'} and len(expected) == len(subjects)
                and {v['storePath']: v['narHash'] for v in roots} == expected
                and all(expected[v['storePath']] == v['narHash'] for v in roots)
                and {v['storePath']: v['narHash'] for v in binding['roots']} == expected
                and len(binding['roots']) == len(expected)
                and {p for t in binding['targets'] for p in t['outputs'].values()} == set(expected), 'Incomplete or conflicting native root coverage')
        require(all(re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\s]+', p) and re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=', h)
                    for p, h in expected.items()), 'Invalid root/NAR identity')
        common.cache_publication.identities(product, cfg, required=True)
        common.cache_publication.closure(product)
        require(re.fullmatch(r'[0-9a-f]{64}', result.get('graphSha256', '')), 'Missing native graph binding')
        boot = result.get('boot', {})
        require(boot.get('producer') == origin and boot.get('disposition') == 'executed'
                and re.fullmatch(r'[0-9a-f]{64}', boot.get('bootLogSha256', ''))
                and boot.get('graphSha256') == result.get('graphSha256') == binding.get('graphSha256')
                and boot.get('isoSha256') == binding.get('isoSha256')
                and re.fullmatch(r'[0-9a-f]{64}', boot.get('isoSha256', '')), 'Unexecuted or changed boot binding')
        require(api('git/ref/heads/main')['object']['sha'] == revision, 'Main changed during preparation')
        return dict(schemaVersion=1, status='prepared-native-data', authorization=False, publicationReady=False,
            sourceRevision=revision, runId=run_id, runAttempt=attempt, rootCount=len(expected), boundDocumentCount=len(DOCUMENTS),
            bootDisposition='executed', narBytesVerified=False, isoBytesVerified=False, riskAcceptanceEvaluated=False)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--directory', type=Path, required=True)
    cli.add_argument('--run', type=int, required=True)
    cli.add_argument('--attempt', type=int, required=True)
    cli.add_argument('--revision', required=True)
    args = cli.parse_args()
    with operations.budget(300):
        result = prepare(args.directory, args.run, args.attempt, args.revision, Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY']))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print('Native preparation blocked: ' + type(error).__name__, file=sys.stderr)
        sys.exit(2)
