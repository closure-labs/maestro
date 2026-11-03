#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive, read-only preparation of one exact native main evidence bundle."""
import argparse
import base64
import gc
from contextlib import contextmanager
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
REFRESH_FILES = ('inputs.sha256', 'Cargo.lock')
PUBLICATION_FILES = ('findings.json', 'effective-policy.json', 'critical-applicability.json', 'source-policy.json')
MAX_JSON = 16 * 1024**2
MAX_REPORT = 64 * 1024**2
MAX_BOOT_LOG = 4 * 1024**2
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


def snapshot(directory, destination, retained=False, publication=False, for_refresh=False):
    require(directory.is_dir() and not directory.is_symlink(), 'Regular evidence directory required')
    total = 0
    extra = (('original-ci-result.json', 'original-boot.log') if retained else ()) + (PUBLICATION_FILES if publication else ()) + (REFRESH_FILES if for_refresh else ())
    for name in (*JSON_FILES, *DOCUMENTS, *extra):
        source = directory / name
        with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            info = os.fstat(stream.fileno())
            cap = (MAX_REPORT if name in ('scans.json', 'security-result.json') else
                   MAX_BOOT_LOG if name == 'original-boot.log' else
                   MAX_JSON if name in (*JSON_FILES, *PUBLICATION_FILES, *REFRESH_FILES, 'original-ci-result.json') else MAX_DOCUMENT)
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


@contextmanager
def bounded_validation():
    # Limit Python object expansion, not just input bytes. Restore before gh:
    # the Go verifier needs a larger virtual address reservation, not this heap.
    before = resource.getrlimit(resource.RLIMIT_AS)
    soft = min(512 * 1024**2, before[0]) if before[0] != resource.RLIM_INFINITY else 512 * 1024**2
    resource.setrlimit(resource.RLIMIT_AS, (soft, before[1]))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_AS, before)


def canonical_digest(value):
    # Do not construct another report-sized serialized string/bytes object.
    digest = hashlib.sha256()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    for piece in encoder.iterencode(value):
        digest.update(piece.encode())
    return digest.hexdigest()


def reports(root):
    # Strict duplicate/nonfinite parsing remains mandatory. Retain only one large
    # decoded report at a time; the scan envelope contains the same native data.
    native = load_json(root / 'security-result.json')
    expected = canonical_digest(native)
    del native
    gc.collect()
    scans = load_json(root / 'scans.json')
    profiles = scans.pop('profiles', None)
    require(isinstance(profiles, dict) and set(profiles) == {'maestro'}, 'Incomplete native scan profile')
    native = profiles['maestro']
    require(canonical_digest(native) == expected, 'Changed native scan content')
    return scans, native


def trusted_run(run_id, attempt, revision):
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0
            and isinstance(revision, str) and re.fullmatch(r'[0-9a-f]{40}', revision), 'Exact producer inputs required')
    run = api(f'actions/runs/{run_id}/attempts/{attempt}')
    require(run.get('id') == run_id and run.get('run_attempt') == attempt and run.get('head_sha') == revision
            and type(run.get('id')) is int and type(run.get('run_attempt')) is int
            and run.get('head_branch') == 'main' and run.get('repository', {}).get('full_name') == REPO
            and run.get('head_repository', {}).get('full_name') == REPO
            and run.get('path', '').split('@')[0] == WORKFLOW and run.get('event') in ('push', 'workflow_dispatch')
            and run.get('status') == 'completed' and run.get('conclusion') == 'success', 'Untrusted native run')


def require_ancestor(source, policy):
    if source != policy:
        ancestry=api('compare/'+source+'...'+policy+'?per_page=1')
        require(ancestry.get('status')=='ahead' and ancestry.get('base_commit',{}).get('sha')==source
                and ancestry.get('merge_base_commit',{}).get('sha')==source,
                'Evidence source is not an ancestor of protected current policy')


def origin_identity(run_id, attempt, revision):
    return dict(GITHUB_REPOSITORY=REPO, GITHUB_SHA=revision, GITHUB_RUN_ID=str(run_id), GITHUB_RUN_ATTEMPT=str(attempt))


def complete(result):
    version = result.get('schemaVersion')
    require(type(version) is int and version in (1, 2), 'Unsupported result schema')
    jobs = ('AUDIT_RESULT', 'COMPARISON_RESULT', 'SCAN_RESULT', 'QUALIFICATION_RESULT') if version == 1 else (
        'AUDIT_RESULT', 'SCAN_RESULT', 'QUALIFICATION_RESULT')
    require(result.get('completeValidationRequired') is True and result.get('jobs') == {
        k: 'success' for k in jobs}, 'Missing complete validation obligation')
    if version == 2:
        require(result.get('validationMode') == 'complete-audit'
                and all(isinstance(result.get(key), str) and re.fullmatch(r'[0-9a-f]{64}', result[key])
                        for key in ('auditReferenceSha256', 'completeAuditSha256'))
                and 'comparisonSha256' not in result, 'Missing or conflicting complete-audit binding')


def retained_boot(root, boot, result, binding, current, selected):
    require(selected is not None, 'Explicit original executed-boot producer required')
    run_id, attempt, revision = selected
    original = origin_identity(run_id, attempt, revision)
    require(original != current, 'Boot proof cannot refer to this invocation producer')
    require(isinstance(boot.get('origin'), dict) and type(boot['origin'].get('runId')) is int
            and ('runAttempt' not in boot['origin'] or type(boot['origin']['runAttempt']) is int)
            and boot['origin'] in (dict(revision=revision, runId=run_id),
                                  dict(revision=revision, runId=run_id, runAttempt=attempt)), 'Changed retained boot origin')
    require(boot.get('bootLogSha256') is None, 'Retained boot cannot claim a current execution log')
    proof = load_json(root / 'original-ci-result.json')
    complete(proof)
    require(proof.get('producer') == original, 'Changed original producer attempt')
    executed = proof.get('boot', {})
    require(type(executed.get('schemaVersion')) is int and executed['schemaVersion'] == 1
            and executed.get('disposition') == 'executed' and executed.get('producer') == original
            and executed.get('origin') == original and executed.get('graphSha256') == proof.get('graphSha256')
            and re.fullmatch(r'[0-9a-f]{64}', proof.get('graphSha256', '')), 'Original boot must be directly executed')
    require(executed.get('bootLogSha256') == file_hash(root / 'original-boot.log')
            and re.search(r'maestro-installer login:|Reached target .*Multi-User System|Started OpenSSH',
                          (root / 'original-boot.log').read_text(), re.I), 'Missing original completed boot log')
    for field in ('isoSha256', 'mediaInput', 'verifierSha256'):
        require(re.fullmatch(r'[0-9a-f]{64}', boot.get(field, ''))
                and executed.get(field) == boot[field], 'Changed retained boot media or verifier')
    if binding.get('isoSha256') is None:
        expected = dict(schemaVersion=1, producer=current, inventorySha256=result['inventoryTransferSha256'],
                        isoSha256=boot['isoSha256'])
        receipt = result.get('inventoryIsoBinding')
        require(isinstance(receipt, dict) and type(receipt.get('schemaVersion')) is int
                and receipt == expected, 'Missing explicit reused ISO/inventory binding')
    else:
        require(binding['isoSha256'] == boot['isoSha256'], 'Changed retained inventory ISO')
    return dict(runId=run_id, runAttempt=attempt, revision=revision)


def refresh_inputs(root, native):
    """Only the three exact original inventory/lockfile bytes can be rescanned."""
    hashes=root/'inputs.sha256';expected=native.get('evidence',{}).get('inputHashes',{})
    require(type(expected.get('size')) is int and 0<hashes.stat().st_size<=4096 and hashes.stat().st_size==expected.get('size')
            and file_hash(hashes)==expected.get('sha256'),'Changed original input checksum binding')
    names={'maestro-system.cdx.json','xen-orchestra-supply.cdx.json','Cargo.lock'};identities={}
    for line in hashes.read_text().splitlines():
        match=re.fullmatch(r'([0-9a-f]{64}) [ *](.+)',line)
        require(match is not None,'Malformed original scan input checksum')
        name=Path(match[2]).name
        require(name in names and name not in identities,'Unexpected or duplicate original scan input')
        identities[name]=match[1]
    require(set(identities)==names and all(file_hash(root/name)==digest for name,digest in identities.items()),
            'Changed original inventory/lockfile bytes')
    system=root/'maestro-system.cdx.json';inventory=native.get('evidence',{}).get('inventory',{})
    require(type(inventory.get('size')) is int and system.stat().st_size==inventory.get('size') and file_hash(system)==inventory.get('sha256'),
            'Original native inventory differs from bound document')
    return identities


@contextmanager
def _verified_bundle(directory, run_id, attempt, revision, policy_path, boot_origin=None, publication=False, for_refresh=False, policy_revision=None):
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0
            and re.fullmatch(r'[0-9a-f]{40}', revision), 'Exact native producer inputs required')
    cfg = common.config(policy_path)
    require(cfg['repository'] == REPO and cfg['profiles'] == ['maestro'], 'Unsupported native profile contract')
    explicit_policy = policy_revision is not None
    policy_revision = revision if policy_revision is None else policy_revision
    require(isinstance(policy_revision,str) and re.fullmatch(r'[0-9a-f]{40}',policy_revision),
            'Exact explicit policy revision required')
    require(api('git/ref/heads/main')['object']['sha'] == policy_revision, 'Selected policy is not current main')
    require_ancestor(revision,policy_revision)
    remote = api('contents/' + POLICY + '?ref=' + policy_revision)
    require(remote.get('encoding') == 'base64' and remote.get('size', MAX_JSON + 1) <= MAX_JSON,
            'Bounded protected policy required')
    require(common.canonical_hash(json.loads(base64.b64decode(remote['content']))) == common.canonical_hash(cfg),
            'Local policy differs from protected source')
    trusted_run(run_id, attempt, revision)
    with tempfile.TemporaryDirectory(prefix='maestro-native-prepare-') as temporary:
        root = Path(temporary)
        snapshot(directory, root, boot_origin is not None, publication, for_refresh)
        for name in ('product.json', 'scans.json', 'ci-result.json'):
            attest(root / name, revision)
        if boot_origin is not None:
            trusted_run(*boot_origin)
            attest(root / 'original-ci-result.json', boot_origin[2])
        with bounded_validation():
            product, result, binding = [load_json(root / name) for name in ('product.json', 'ci-result.json', 'inventory-binding.json')]
            scans, native = reports(root)
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
            origin = origin_identity(run_id, attempt, revision)
            inputs=refresh_inputs(root,native) if for_refresh else None
            complete(result)
            require(type(binding.get('schemaVersion')) is int and binding['schemaVersion'] == 2, 'Unsupported inventory schema')
            require(result.get('producer') == binding.get('producer') == origin, 'Changed result producer attempt')
            require(result.get('nativeScanSha256') == file_hash(root / 'security-result.json'), 'Changed native scan bytes')
            require(result.get('inventoryTransferSha256') == file_hash(root / 'inventory-binding.json'), 'Changed inventory binding bytes')
            require(binding.get('phase') == 'inventory' and binding.get('transport') is None
                    and set(binding.get('evidenceFiles', {})) == set(DOCUMENTS), 'Incomplete local inventory binding')
            require(all(file_hash(root / n) == h for n, h in binding['evidenceFiles'].items()), 'Changed inventory document bytes')
            require(common.timestamp(scans['scannedAt']) <= common.timestamp(native['scannedAt'])
                    and common.timestamp(scans['scannedAt']) < common.timestamp(scans['expiresAt'])
                    and (for_refresh or common.timestamp(scans['expiresAt']) > common.dt.datetime.now(common.dt.timezone.utc))
                    and common.timestamp(scans['expiresAt']) - common.timestamp(scans['scannedAt']) <= common.dt.timedelta(hours=24),
                    'Expired or invalid scan envelope')
            spec = importlib.util.spec_from_file_location('native_check', os.environ.get('MAESTRO_SECURITY_NATIVE_CHECK_SOURCE', Path(__file__).with_name('security-native-check.py')))
            check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
            require(isinstance(native.get('securityContext'), dict) and native['securityContext'].get('schema') == 2, 'Complete installer security context required')
            normalized = []
            (check.inventory_identity if for_refresh else check.check)(native, cfg, capture=normalized.extend)
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
            require(boot.get('producer') == origin
                    and boot.get('graphSha256') == result.get('graphSha256') == binding.get('graphSha256')
                    and re.fullmatch(r'[0-9a-f]{64}', boot.get('isoSha256', '')), 'Changed current boot binding')
            disposition = boot.get('disposition')
            original = None
            if disposition == 'executed':
                require(boot_origin is None and re.fullmatch(r'[0-9a-f]{64}', boot.get('bootLogSha256', ''))
                        and boot.get('isoSha256') == binding.get('isoSha256'), 'Unexecuted or changed boot binding')
            elif disposition == 'verified-retained':
                original = retained_boot(root, boot, result, binding, origin, boot_origin)
            else:
                raise ValueError('Unsupported boot disposition')
        require(api('git/ref/heads/main')['object']['sha'] == policy_revision, 'Main changed during preparation')
        receipt = dict(schemaVersion=1, status='prepared-native-data', authorization=False, publicationReady=False,
            sourceRevision=revision, runId=run_id, runAttempt=attempt, rootCount=len(expected), boundDocumentCount=len(DOCUMENTS),
            bootDisposition=disposition, bootOrigin=original, narBytesVerified=False, isoBytesVerified=False, riskAcceptanceEvaluated=False)

        if explicit_policy:receipt['policyRevision']=policy_revision
        if for_refresh:
            receipt.update(status='verified-inventory-for-refresh', currentHealthVerified=False)
        # Keep one frozen bundle and one authenticated native object for the
        # consumer. No authority result persists beyond this context/invocation.
        yield dict(directory=root, receipt=receipt, native=native, scans=scans,
                   product=product, result=result, binding=binding, policyHash=common.canonical_hash(cfg), normalizedFindings=normalized, inventoryOnly=for_refresh, inputIdentities=inputs)


@contextmanager
def verified_bundle(directory, run_id, attempt, revision, policy_path, boot_origin=None, publication=False, policy_revision=None):
    with _verified_bundle(directory, run_id, attempt, revision, policy_path, boot_origin, publication, policy_revision=policy_revision) as bundle:
        yield bundle


@contextmanager
def verified_inventory(directory, run_id, attempt, revision, policy_path, boot_origin=None, policy_revision=None):
    """Immutable original inputs only, for a new independently fresh rescan."""
    with _verified_bundle(directory, run_id, attempt, revision, policy_path, boot_origin, for_refresh=True, policy_revision=policy_revision) as bundle:
        yield bundle


def prepare(directory, run_id, attempt, revision, policy_path, boot_origin=None, policy_revision=None):
    with verified_bundle(directory, run_id, attempt, revision, policy_path, boot_origin, policy_revision=policy_revision) as bundle:
        return bundle['receipt']


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--directory', type=Path, required=True)
    cli.add_argument('--run', type=int, required=True)
    cli.add_argument('--attempt', type=int, required=True)
    cli.add_argument('--revision', required=True)
    cli.add_argument('--policy-revision', help='Explicit current main policy; product remains the exact qualified ancestor')
    cli.add_argument('--boot-origin-run', type=int)
    cli.add_argument('--boot-origin-attempt', type=int)
    cli.add_argument('--boot-origin-revision')
    args = cli.parse_args()
    selected = (args.boot_origin_run, args.boot_origin_attempt, args.boot_origin_revision)
    require(all(v is None for v in selected) or all(v is not None for v in selected), 'Complete explicit boot origin required')
    selected = None if all(v is None for v in selected) else selected
    with operations.budget(300):
        result = prepare(args.directory, args.run, args.attempt, args.revision, Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY']), selected, policy_revision=args.policy_revision)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError, MemoryError, subprocess.SubprocessError) as error:
        print('Native preparation blocked: ' + type(error).__name__, file=sys.stderr)
        sys.exit(2)
