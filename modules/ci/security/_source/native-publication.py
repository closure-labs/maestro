#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native evidence consumers: mandatory policy, selected cache writes and cold readback."""
import argparse
import base64
from collections import Counter
from contextlib import contextmanager
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import resource


def module(name, variable, fallback):
    spec = importlib.util.spec_from_file_location(name, os.environ.get(variable, Path(__file__).parent / fallback))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


native = module('native_prepare', 'MAESTRO_NATIVE_PREPARE_SOURCE', 'native-prepare.py')
verdict = module('native_verdict', 'MAESTRO_SECURITY_VERDICT_SOURCE', 'security-verdict.py')
risk = module('native_risk', 'MAESTRO_NATIVE_RISK_SOURCE', 'native-risk.py')
require = native.require
POLICY = 'modules/ci/security/_source/security-policy.json'
CACHE = 'https://maestro.cachix.org'
KEY = 'maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0='
MAX_REVIEW_BYTES = 64 * 1024**2

# These protected-source policy/verifier files are part of every risk scope.
# This is a data digest, not a persisted authority capability.
RISK_POLICY_FILES=(
    '.github/CODEOWNERS', 'VERSION', '.github/workflows/publication.yml',
    '.github/workflows/consumer-probe.yml',
    '.github/workflows/release.yml', '.github/workflows/release-publication.yml',
    'modules/ci/authority/_source/decision-policy.json',
    'modules/ci/security/_source/security-policy.json',
    'modules/ci/security/_source/native-risk.py',
    'modules/ci/security/_source/native-publication.py',
    'modules/ci/security/_source/native-prepare.py',
    'modules/ci/security/_source/native-refresh.py',
    'modules/ci/security/_source/native-health.py',
    '.github/workflows/security.yml',
    'modules/ci/security/_source/security-native-check.py',
    'modules/ci/security/_source/security-verdict.py',
    'modules/ci/security/_source/security-normalize.py',
    'modules/ci/security/_source/security-scan.sh',
    'modules/release/publication/_source/native-release-stage.py',
    'modules/release/publication/_source/native-release-publish.py',
    'modules/release/publication/_source/publication-assets.py',
    'modules/release/publication/_source/release-attestations.sh',
    'modules/release/publication/_source/release-split.sh',
)


class MandatoryVerdictError(ValueError):
    def __init__(self, outcome):
        self.outcome = outcome
        super().__init__('Mandatory native vulnerability verdict blocks publication')


def bound_json(bundle, name, key):
    path = bundle.get('policyDirectory', bundle['directory']) / name
    expected = bundle['native'].get('evidence', {}).get(key, {})
    require(type(expected.get('size')) is int and path.stat().st_size == expected['size']
            and native.file_hash(path) == expected.get('sha256'), 'Missing or changed policy/finding evidence: ' + name)
    return native.load_json(path)


def policy_verdict(bundle, source_policy, blocking=None):
    """Report mode is observation metadata; violations always block this boundary."""
    source = bound_json(bundle, 'source-policy.json', 'sourcePolicy')
    require(not source.get('exceptions') and not source.get('dispositions'), 'Source-policy exceptions cannot substitute for explicit findings-risk review')
    findings = bound_json(bundle, 'findings.json', 'findings')
    effective = bound_json(bundle, 'effective-policy.json', 'effectivePolicy')
    applicability = bound_json(bundle, 'critical-applicability.json', 'applicability')
    require(source == source_policy, 'Scan source policy differs from protected current policy')
    key = lambda row: tuple(row[k] for k in sorted(verdict.KEYS))
    reviewed = {key(row) for row in [*source['dispositions'], *source['exceptions']]}
    expected = dict(source, dispositions=[*source['dispositions'],
        *(row for row in applicability['dispositions'] if key(row) not in reviewed)])
    require(effective == expected, 'Effective policy contains unbound decisions')
    violations = verdict.evaluate(findings, effective)
    normalized = [row for row in bundle['normalizedFindings'] if row['severity'] in ('High', 'Critical', 'Unknown')]
    if blocking is not None:blocking.update(findings=findings,raw=violations,normalized=normalized)
    return dict(status='blocked' if violations or normalized else 'clear',
                normalizedBlockingIdentities=len(normalized),
                normalizedSeverities=dict(Counter(row['severity'] for row in normalized)),
                blockingRows=len(violations), severities=dict(Counter(row['severity'] for row in violations)),
                policyMode=source['mode'], mandatory=True)


def protected_policy(bundle, policy_path):
    revision = bundle['receipt'].get('policyRevision',bundle['receipt']['sourceRevision'])
    remote = native.api('contents/' + POLICY + '?ref=' + revision)
    require(remote.get('encoding') == 'base64' and remote.get('size', native.MAX_JSON + 1) <= native.MAX_JSON,
            'Bounded protected security policy required')
    source = json.loads(base64.b64decode(remote['content']))
    require(native.load_json(policy_path) == source, 'Packaged security policy differs from protected source')
    return source


def fresh(bundle, policy_path, policy_digest):
    require(native.api('git/ref/heads/main')['object']['sha'] == bundle['receipt'].get('policyRevision',bundle['receipt']['sourceRevision']),
            'Main changed before native consumer operation')
    require(native.file_hash(policy_path) == policy_digest, 'Local security policy changed')
    cfg = native.common.config(Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY']))
    require(native.common.canonical_hash(cfg) == bundle['policyHash'], 'Native scope/freshness policy changed')
    if bundle.get('_riskAcceptance'):
        risk.live(native.api,bundle['_riskAcceptance'],bundle['receipt'].get('policyRevision',bundle['receipt']['sourceRevision']))
    now = native.common.dt.datetime.now(native.common.dt.timezone.utc)
    scanned = native.common.timestamp(bundle['native']['scannedAt'])
    built = native.common.timestamp(bundle['native']['database']['built'])
    require(scanned <= now and now - scanned <= native.common.dt.timedelta(hours=cfg['maxEvidenceAgeHours'])
            and built <= scanned and now - built <= native.common.dt.timedelta(hours=cfg['maxDatabaseAgeHours'])
            and native.common.timestamp(bundle.get('healthManifest', bundle['scans'])['expiresAt']) > now,
            'Native consumer evidence expired')


def store_metadata(paths):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        def cap():resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024**2, 16 * 1024**2))
        native.operations.run(['nix', 'path-info', '--json', '--recursive', *paths], stdout=out, stderr=err,
                              check=True, timeout=120, preexec_fn=cap)
        out.seek(0)
        with native.bounded_validation():
            return json.load(out)


def consume(bundle, policy_path, operation, transport=None, execute=native.operations.run, probe=None, restore=None, inspect=None, query=store_metadata, release=None, review_operation='publish'):
    require(bundle.get('inventoryOnly') is not True, 'Inventory identity is not current publication health')
    policy_digest = native.file_hash(policy_path)
    fresh(bundle, policy_path, policy_digest)
    source_policy = protected_policy(bundle, policy_path)
    blocking={}
    with native.bounded_validation():
        outcome = policy_verdict(bundle, source_policy, blocking)
    if operation in ('publish','release') and not os.environ.get('NATIVE_FINDINGS_CONTEXT_SHA256') and outcome['status']!='clear':
        raise MandatoryVerdictError(outcome)
    if operation in ('review','publish','release'):
        root=Path(os.environ.get('MAESTRO_SYSTEM_ROOT',os.getcwd()))
        files={name:root/name for name in RISK_POLICY_FILES}
        target=review_operation if operation=='review' else operation
        state=risk.plan(bundle,blocking['findings'],files,native.api,target)
        if operation=='review':
            return dict(status='awaiting-explicit-findings-risk-review',authorization=False,publicationReady=False,
                verdict=outcome,review=state,rawFindings=blocking['findings'],normalizedFindings=bundle['normalizedFindings'],
                notice='Approving findings-risk-review accepts the exact displayed vulnerability risk, including high/critical findings, for this publication only.')
        state['rebuild']=lambda:risk.context(bundle,bound_json(bundle,'findings.json','findings'),files,target,state['context']['runId'])
        bundle['_riskAcceptance']=state
        proof=risk.approval(native.api,state)
        outcome.update(status='clear',riskAcceptance=proof)
    if outcome['status'] != 'clear':
        raise MandatoryVerdictError(outcome)
    if operation == 'check':
        return dict(status='native-policy-clear', authorization=False, publicationReady=False, verdict=outcome)
    if operation == 'release':
        require(isinstance(release,dict) and set(release)=={'directory','iso'}, 'Exact staged release inputs required')
        writer=module('native_release_writer','MAESTRO_NATIVE_RELEASE_WRITER_SOURCE','../../../release/publication/_source/native-release-publish.py')
        return dict(writer.publish(bundle,release['directory'],release['iso'],policy_path),verdict=outcome)
    if probe is None:
        reader = module('native_consumer_probe', 'MAESTRO_NATIVE_CONSUMER_SOURCE', '../../../release/consumer/_source/consumer-probe.py')
        probe = reader.probe
    if operation == 'probe':
        result = probe(bundle['product'], CACHE, KEY)
        fresh(bundle, policy_path, policy_digest)
        return dict(result, verdict=outcome)
    require(operation == 'publish' and os.environ.get('MAESTRO_NATIVE_PUBLICATION_ENABLED') == 'true'
            and os.environ.get('GITHUB_REPOSITORY') == native.REPO
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and os.environ.get('GITHUB_SHA') == bundle['receipt'].get('policyRevision',bundle['receipt']['sourceRevision']),
            'Native writer remains disabled or has the wrong protected policy context')
    destinations = module('native_destinations', 'PUBLICATION_DESTINATIONS_SOURCE', '../../authority/_source/decisions/destinations.py')
    observe = inspect or (lambda product: destinations.cache(product, CACHE,
        upstreams=('https://cache.nixos.org', 'https://xen-orchestra-ce.cachix.org')))
    observation = observe(bundle['product'])
    if observation['status'] == 'verified':
        result = probe(bundle['product'], CACHE, KEY)
        fresh(bundle, policy_path, policy_digest)
        return dict(result, verdict=outcome)
    require(observation['status'] == 'partial', 'Conflicting or unavailable cache destination')
    scope = native.common.cache_publication.closure(bundle['product'])
    require(scope is not None and isinstance(observation.get('missing'), list)
            and bool(observation['missing']) and set(observation['missing']) <= set(scope), 'Invalid signed cache observation')
    require(os.environ.get('CACHIX_MAESTRO_PUBKEY') == KEY and os.environ.get('CACHIX_MAESTRO_AUTH_TOKEN'), 'Existing cache identity/credential required')
    if transport is None:
        stage = module('native_stage', 'MAESTRO_NATIVE_STAGE_SOURCE', 'native-stage.py')
        transport = stage.transport(bundle['receipt']['runId'], bundle['receipt']['sourceRevision'], bundle['directory'] / 'transport')
    distribution = module('native_distribution', 'MAESTRO_DISTRIBUTION_CACHE_SOURCE', '../../graph/_source/distribution-cache.py')
    roots = [{'storePath': row['storePath'], 'narHash': row['narHash']}
             for row in [*bundle['product']['products'].values(), *bundle['product']['roots'].values()]]
    fresh(bundle, policy_path, policy_digest)
    retained_path = bundle['directory'] / 'retained-closure.json'
    (restore or distribution.restore)(transport, bundle['scans']['transport'], roots, closure_metadata=retained_path)
    native.common.cache_publication.scoped_metadata(bundle['product'], native.load_json(retained_path), query)
    selected = native.common.cache_publication.identities(bundle['product'], native.common.config(Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY'])), required=True)
    fresh(bundle, policy_path, policy_digest)
    observation = observe(bundle['product'])
    scope = native.common.cache_publication.closure(bundle['product'])
    require(observation['status'] in ('partial', 'verified'), 'Conflicting cache destination after restore')
    missing = observation.get('missing', [])
    require(scope is not None and set(missing) <= set(scope), 'Upload paths exceed signed selected cache scope')
    env = dict(os.environ, CACHIX_AUTH_TOKEN=os.environ['CACHIX_MAESTRO_AUTH_TOKEN'])
    # Fixed CLI and signed selected paths only. No evaluation, build or uploaded
    # candidate code executes in the writer; no whole-store/cache watch.
    if missing:
        fresh(bundle, policy_path, policy_digest)
        execute(['cachix', 'push', 'maestro', *sorted(missing)], env=env, check=True, timeout=900)
    result = probe(bundle['product'], CACHE, KEY)
    fresh(bundle, policy_path, policy_digest)
    return dict(result, verdict=outcome)


@contextmanager
def selected(directory,run,attempt,revision,origin=None,*,policy_revision=None,
             health_run=None,health_attempt=None,health_directory=None):
    """Share one exact original/fresh evidence selection across native consumers."""
    require(policy_revision is None or re.fullmatch(r'[0-9a-f]{40}',policy_revision),'Exact explicit policy revision required')
    require((health_run is None)==(health_attempt is None),'Complete exact fresh-health producer required')
    require(health_directory is None or health_run is not None,'Fresh-health directory needs exact producer')
    loader=module('native_stage','MAESTRO_NATIVE_STAGE_SOURCE','native-stage.py')
    if directory is None:
        directory=Path(os.environ['RUNNER_TEMP'])/'native-candidate'
        (loader.stage_refresh if health_run is not None else loader.stage)(directory,run,attempt,revision,origin)
    policy=Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY'])
    if health_run is None:
        with native.verified_bundle(directory,run,attempt,revision,policy,origin,publication=True,
                policy_revision=policy_revision) as bundle:yield bundle
    else:
        fetch=None
        if health_directory is None:
            health_directory=Path(os.environ['RUNNER_TEMP'])/'native-health'
            fetch=lambda health_revision:loader.stage_health(health_directory,health_run,health_revision)
        health=module('native_health','MAESTRO_NATIVE_HEALTH_SOURCE','native-health.py')
        with native.verified_inventory(directory,run,attempt,revision,policy,origin,policy_revision=policy_revision) as original:
            with health.verified(original,health_directory,health_run,health_attempt,native.common.config(policy),fetch=fetch) as bundle:
                yield bundle


def emit(result, error=False):
    value = json.dumps(result, sort_keys=True)
    target = os.environ.get('NATIVE_RESULT_FILE')
    if target:
        try:
            with Path(target).open('x') as stream:
                stream.write(value + '\n')
        except OSError:
            print('Could not retain native diagnostic receipt', file=sys.stderr)
    print(value, file=sys.stderr if error else sys.stdout)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('operation', choices=('check', 'probe', 'publish', 'release', 'review'))
    cli.add_argument('--review-operation',choices=('publish','release'),default='publish')
    cli.add_argument('--directory', type=Path)
    cli.add_argument('--release-directory',type=Path);cli.add_argument('--release-iso',type=Path)
    cli.add_argument('--run', type=int, required=True); cli.add_argument('--attempt', type=int, required=True)
    cli.add_argument('--revision', required=True); cli.add_argument('--transport-directory', type=Path)
    cli.add_argument('--policy-revision', help='Explicit current main policy; does not change product identity')
    cli.add_argument('--health-run', type=int); cli.add_argument('--health-attempt', type=int)
    cli.add_argument('--health-directory', type=Path)
    cli.add_argument('--boot-origin-run', type=int); cli.add_argument('--boot-origin-attempt', type=int)
    cli.add_argument('--boot-origin-revision'); args = cli.parse_args()
    require(args.policy_revision is None or re.fullmatch(r'[0-9a-f]{40}',args.policy_revision), 'Exact explicit policy revision required')
    release=dict(directory=args.release_directory,iso=args.release_iso) if args.operation=='release' else None
    require((args.operation=='release' and all(v is not None for v in (args.release_directory,args.release_iso)))
        or (args.operation!='release' and args.release_directory is None and args.release_iso is None), 'Complete release-only inputs required')
    origin = (args.boot_origin_run, args.boot_origin_attempt, args.boot_origin_revision)
    require(all(v is None for v in origin) or all(v is not None for v in origin), 'Complete explicit boot origin required')
    origin = None if all(v is None for v in origin) else origin
    require((args.health_run is None) == (args.health_attempt is None), 'Complete exact fresh-health producer required')
    require(args.health_directory is None or args.health_run is not None, 'Fresh-health directory needs exact producer')
    with native.operations.budget(3300),selected(args.directory,args.run,args.attempt,args.revision,origin,
            policy_revision=args.policy_revision,health_run=args.health_run,health_attempt=args.health_attempt,
            health_directory=args.health_directory) as bundle:
        result=consume(bundle,Path(os.environ['MAESTRO_NATIVE_SECURITY_POLICY']),args.operation,args.transport_directory,release=release,review_operation=args.review_operation)
        if args.health_run is not None:result['healthProducer']=bundle['healthManifest']['producer']
    if args.operation=='review':
        review_file=os.environ.get('NATIVE_RISK_REVIEW_FILE')
        require(review_file,'Explicit review artifact output required')
        target=Path(review_file);created=False
        try:
            with target.open('xb') as stream:
                created=True;length=0
                for chunk in json.JSONEncoder(sort_keys=True,allow_nan=False).iterencode(result):
                    raw=chunk.encode();length+=len(raw)
                    require(length<MAX_REVIEW_BYTES,'Bounded findings review document required')
                    stream.write(raw)
                stream.write(b'\n')
        except Exception:
            if created:target.unlink(missing_ok=True)
            raise
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
            stream.write('context_sha256='+result['review']['contextSha256']+'\n')
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as stream:
            stream.write('## Explicit findings-risk review\n'+result['notice']+'\n\n')
            stream.write('Context SHA-256: `'+result['review']['contextSha256']+'`\n\n')
            stream.write('Review the immutable `maestro-findings-review` artifact for exact product, evidence, policy and finding identities.\n\n')
            stream.write('```json\n'+json.dumps(result['verdict'],sort_keys=True)+'\n```\n')
        result={k:v for k,v in result.items() if k not in ('rawFindings','normalizedFindings')}
    result.update(authorization=False, sourceRevision=args.revision, sourceRun=args.run, sourceAttempt=args.attempt)
    if args.policy_revision is not None:result['policyRevision']=args.policy_revision
    emit(result)


if __name__ == '__main__':
    try:
        main()
    except MandatoryVerdictError as error:
        emit(dict(status='blocked', authorization=False, verdict=error.outcome), error=True)
        sys.exit(2)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, MemoryError, RecursionError) as error:
        emit(dict(status='blocked', authorization=False, error=type(error).__name__), error=True)
        sys.exit(2)
