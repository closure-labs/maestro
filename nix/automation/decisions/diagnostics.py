# SPDX-License-Identifier: Apache-2.0
"""Execution evidence and bounded public summaries; never authority or a retry."""
import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import copy
import tempfile
import diagnostic_artifacts as artifacts
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid
import publication_receipts
import diagnostic_requests as requests
import datetime as dt

STARTED = time.monotonic()
EXECUTION = uuid.uuid4().hex
COUNTERS = {}
GATE_DISPLAY = {}
PROFILES = {}
BOUNDARY = ContextVar('diagnostic_boundary', default='native-scan')
PROFILE_CATEGORIES = {
    'gatePhases': {'gate', 'policy', 'ledger', 'scans', 'ancestry', 'admission', 'product', 'release', 'refresh'},
    'transport': {'github-api', 'attestation', 'public-http', 'registry', 'other'},
    'packetOperations': {'manifest', 'descriptor', 'metadata-member', 'payload-member', 'push', 'other'},
}


def profile(group, category, *, calls=0, wrappers=0, launches=0, retries=0, captured=0, reused=0, seconds=0, failures=0,
            connections=None, starts=None, denied=None, metadata=None, measured=None, unmeasured=None):
    if group not in PROFILE_CATEGORIES or category not in PROFILE_CATEGORIES[group]:
        raise ValueError('Invalid diagnostic category')
    if not enabled():
        return
    with LOCK:
        extra = {key: value for key, value in (
            ('successfulConnections', connections), ('requestStarts', starts), ('deniedRequestStarts', denied),
            ('metadataBytes', metadata), ('measuredReads', measured), ('unmeasuredReads', unmeasured)) if value is not None}
        if extra and (group != 'transport' or category != 'public-http' or any(type(v) is not int or v < 0 for v in extra.values())):
            raise ValueError('Invalid public transport measurement')
        if group == 'transport':
            with requests.scope(transport=category):
                requests.transport(calls=calls, wrapperCalls=wrappers, subprocessLaunches=launches,
                                   explicitRetries=retries, capturedBytes=captured, immutableBytesReused=reused,
                                   elapsedSeconds=seconds, failures=failures, **extra)
        value = PROFILES.setdefault(group, {}).setdefault(category, {
            'calls': 0, 'wrapperCalls': 0, 'subprocessLaunches': 0, 'explicitRetries': 0,
            'capturedBytes': 0, 'immutableBytesReused': 0, 'elapsedSeconds': 0, 'failures': 0,
            'httpAttempts': None, 'wireBytes': None})
        for key, amount in extra.items():
            value[key] = value.get(key, 0) + amount
        for key, amount in (('calls', calls), ('wrapperCalls', wrappers), ('subprocessLaunches', launches), ('explicitRetries', retries),
                            ('capturedBytes', captured), ('immutableBytesReused', reused),
                            ('elapsedSeconds', seconds), ('failures', failures)):
            if type(amount) not in (int, float) or not 0 <= amount < 10**20:
                raise ValueError('Invalid diagnostic measurement')
            value[key] = round(value[key] + amount, 6) if key == 'elapsedSeconds' else value[key] + amount


@contextmanager
def measuring(group, category):
    started = time.monotonic()
    failed = 0
    try:
        # Only the innermost phase owns a request. Existing duration scopes
        # intentionally remain nested and must not be summed as wall time.
        with requests.scope(**({'phase': category} if group == 'gatePhases' else {})):
            yield
    except BaseException:
        failed = 1
        raise
    finally:
        profile(group, category, calls=1, seconds=time.monotonic() - started, failures=failed)


def measured(group, category):
    def decorate(function):
        @wraps(function)
        def invoke(*args, **kwargs):
            with measuring(group, category):
                return function(*args, **kwargs)
        return invoke
    return decorate


@contextmanager
def boundary(name):
    if name not in ('native-scan', 'gate', 'handoff', 'selection'):
        raise ValueError('Invalid diagnostic boundary')
    token = BOUNDARY.set(name)
    try:
        yield
    finally:
        BOUNDARY.reset(token)


def freshness(remaining, valid, allow_expired, lifetime='evidence'):
    if lifetime not in ('evidence', 'database'):
        raise ValueError('Invalid freshness lifetime')
    if enabled():
        value = {'schema': 1, 'execution': EXECUTION, 'boundary': BOUNDARY.get(),
                 'lifetime': lifetime, 'remainingSeconds': round(remaining, 3), 'validLifetime': bool(valid),
                 'expired': remaining <= 0, 'allowExpired': bool(allow_expired),
                 'elapsedSeconds': round(time.monotonic() - STARTED, 3)}
        artifacts.atomic_write(directory(), uuid.uuid4().hex + '.freshness.json',
                               (json.dumps(value, sort_keys=True) + '\n').encode(), immutable=True)


def transport_category(args):
    # Inspect argv only to choose fixed labels. Never retain any argument.
    tool = Path(args[0]).name if args else ''
    if tool == 'gh' and args[1:2] == ['api']:
        return 'github-api'
    if tool == 'gh' and args[1:3] == ['attestation', 'verify']:
        return 'attestation'
    return {'curl': 'public-http', 'oras': 'registry'}.get(tool, 'other')


def captured_bytes(value):
    return len(value.encode()) if isinstance(value, str) else len(value) if isinstance(value, bytes) else 0

LOCK = threading.Lock()
COUNTER_NAMES = ('gateInvocations', 'apiWrapperInvocations', 'apiTransportInvocations',
                 'publicTransportInvocations', 'immutableBytesReused', 'metadataCacheHits',
                 'metadataBytesReused', 'metadataRegistryOperationsAvoided')
KINDS = {'admission', 'publication', 'publication-journal', 'publication-assets', 'destinations', 'gate', 'handoff', 'packet-metadata'}


def enabled():
    return os.environ.get('MAESTRO_CI_DIAGNOSTICS') == 'true'


def count(name, amount=1):
    if enabled():
        with LOCK:
            if name in requests.COUNTERS:
                transport = 'public-http' if name == 'publicTransportInvocations' else 'github-api'
                with requests.scope(transport=transport):
                    requests.add('counters', name, amount)
            COUNTERS[name] = COUNTERS.get(name, 0) + amount


def directory():
    root = Path(os.environ['RUNNER_TEMP']) / 'publication-diagnostics'
    return artifacts.regular_directory(root, create=True)


def identity(value):
    return value if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value) else None


def bounded_count(value):
    return value if type(value) is int and 0 <= value < 10**20 else None


def collection_count(result, collection, fallback):
    value = result.get(collection)
    return len(value) if isinstance(value, (list, dict)) else bounded_count(result.get(fallback))


def record(result, kind=None, logged=True, context=None):
    if kind is None:
        source = Path(os.sys.argv[0])
        kind = source.stem
        packaged = re.fullmatch(r'[a-z0-9]{32}-(.+)', kind)
        if source.parent == Path('/nix/store') and packaged:
            kind = packaged[1]
    if not enabled() or kind not in KINDS:
        return None
    context = context if isinstance(context, dict) else {}
    raw = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    digest = hashlib.sha256(raw).hexdigest()
    name = uuid.uuid4().hex
    reference = artifacts.store(directory(), raw)
    outcome = result.get('status')
    if outcome not in ('allowed', 'covered', 'blocked', 'verified', 'partial', 'missing', 'conflict', 'unavailable', 'complete', 'pending', 'published', 'staged'):
        outcome = 'completed'
    producer = result.get('producer', {})
    if not isinstance(producer, dict):
        producer = {}
    summary = {'schema': 1, 'execution': EXECUTION, 'kind': kind, 'status': outcome,
               'productHash': identity(result.get('productHash', context.get('productHash'))),
               'proposalHash': identity(result.get('proposalHash')),
               'decisionHash': identity(result.get('decisionHash')),
               'producerRevision': identity(producer.get('revision')),
               'producerRun': bounded_count(producer.get('runId')),
               'producerAttempt': bounded_count(producer.get('runAttempt')),
               'rootCount': collection_count(result, 'expected', 'rootCount'),
               'findingCount': collection_count(result, 'findings', 'findingCount'),
               'elapsedSeconds': round(time.monotonic() - STARTED, 3), 'evidenceDigest': digest,
               'resultReference': reference,
               'measurements': {key: COUNTERS.get(key, 0) for key in COUNTER_NAMES},
               # gh and curl can retry internally. Their process invocations
               # must never be presented as a count of actual HTTP attempts.
               'httpAttempts': None, 'logBytes': 0}
    # Only display fields pass between records in this invocation. Status,
    # approvals and authorization results are never reused from this context.
    fields = ('productHash', 'producerRevision', 'producerRun', 'producerAttempt', 'rootCount', 'findingCount')
    with LOCK:
        if kind == 'gate' and summary['productHash'] is not None:
            GATE_DISPLAY.clear()
            GATE_DISPLAY.update({key: summary[key] for key in fields})
        elif (kind in ('publication', 'admission', 'publication-journal', 'publication-assets', 'handoff')
              and summary['productHash'] is not None and summary['productHash'] == GATE_DISPLAY.get('productHash')):
            for key in fields:
                if summary[key] is None:
                    summary[key] = GATE_DISPLAY.get(key)
    value = json.dumps(summary, sort_keys=True, separators=(',', ':')) + '\n'
    assert len(value.encode()) <= 4096
    while logged and summary['logBytes'] != len(value.encode()):
        summary['logBytes'] = len(value.encode())
        value = json.dumps(summary, sort_keys=True, separators=(',', ':')) + '\n'
    assert len(value.encode()) <= 4096
    snapshot()
    artifacts.atomic_write(directory(), name + '.summary.json', value.encode(), immutable=True)
    return value


def snapshot():
    if enabled():
        with LOCK:
            profiles = copy.deepcopy(PROFILES)
            counters = {key: COUNTERS.get(key, 0) for key in COUNTER_NAMES}
            artifacts.atomic_write(directory(), EXECUTION + '.profile.json',
                                   (json.dumps({'schema': 1, 'execution': EXECUTION, 'profiles': profiles,
                                                'requests': requests.snapshot(), 'measurements': counters}, sort_keys=True) + '\n').encode())


def staged(function):
    """Record native Python boundaries without changing their stdout or status."""
    @wraps(function)
    def invoke(*args, **kwargs):
        if not enabled():
            return function(*args, **kwargs)
        source = Path(os.sys.argv[0]).stem
        source = re.sub(r'^[0-9a-z]{32}-', '', source)
        source = {'decision-download': 'selection', 'decision-retained': 'selection',
                  'decision-handoff-fetch': 'packet-materialization'}.get(source, source)
        name = source if source in requests.STAGES else 'other'
        member = uuid.uuid4().hex + '.stage.json'
        started = time.monotonic()
        value = {'schema': 1, 'execution': EXECUTION, 'stage': name,
                 'startedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                 'elapsedSeconds': None, 'outcome': 'unknown', 'exitCode': None}
        artifacts.atomic_write(directory(), member, (json.dumps(value, sort_keys=True) + '\n').encode())
        with requests.scope(stage=name):
            try:
                result = function(*args, **kwargs)
            except BaseException as error:
                value['outcome'] = 'interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else 'failure'
                if isinstance(error, SystemExit):
                    value['exitCode'] = error.code if type(error.code) is int else 0 if error.code is None else 1
                    value['outcome'] = 'success' if value['exitCode'] == 0 else 'interrupted' if value['exitCode'] in (130, 143) else 'failure'
                # Preserve the original exception even if diagnostic finalization fails.
                try:
                    finish_stage(member, value, started)
                except (OSError, ValueError):
                    pass
                raise
            else:
                value['exitCode'] = result if type(result) is int else 0
                value['outcome'] = 'success' if value['exitCode'] == 0 else 'failure'
                finish_stage(member, value, started)
                return result
    return invoke


def finish_stage(member, value, started):
    value['elapsedSeconds'] = round(time.monotonic() - started, 6)
    # Completion is durable only after this execution's measurements are saved.
    snapshot()
    artifacts.atomic_write(directory(), member, (json.dumps(value, sort_keys=True) + '\n').encode())


def capture_receipts(root):
    captures = {}
    for destination in ('cache', 'flakehub', 'github'):
        name = destination + '-receipt.json'
        target = root / name
        if target.is_symlink():
            raise ValueError('Unsafe diagnostic receipt')
        target.unlink(missing_ok=True)
        source = Path(os.environ['RUNNER_TEMP']) / name
        if not source.exists():
            captures[destination] = 'missing'
            continue
        try:
            if source.is_symlink() or not source.is_file() or source.stat().st_size > 128 * 1024:
                raise ValueError('Invalid receipt file')
            raw = source.read_bytes()
            value = json.loads(raw)
            if not isinstance(value, dict) or not isinstance(value.get('productHash'), str) or not re.fullmatch(r'[a-f0-9]{64}', value['productHash']):
                raise ValueError('Invalid receipt identity')
            publication_receipts.validate(value, value['productHash'], destination)
            artifacts.atomic_write(root, name, raw)
            captures[destination] = 'captured'
        except (OSError, ValueError, KeyError, TypeError):
            captures[destination] = 'invalid'
    return captures


def manifest():
    root = directory()
    receipts = capture_receipts(root)
    files = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Unsafe diagnostic member')
        if path.is_dir():
            if path.relative_to(root).as_posix() != 'objects':
                raise ValueError('Unexpected diagnostic directory')
        elif path != root / 'manifest.json':
            name = path.relative_to(root).as_posix()
            files[name] = artifacts.fingerprint(root, name)
    occurrences = []
    for name in sorted(files):
        if name.endswith('.summary.json'):
            summary = artifacts.read_json(root, name)
            occurrences.append({'summary': name, 'execution': summary['execution'], 'kind': summary['kind'],
                                'elapsedSeconds': summary['elapsedSeconds'], 'resultReference': summary['resultReference']})
    profiles = {}
    executions = {}
    for name in sorted(files):
        if name.endswith('.profile.json'):
            document = artifacts.read_json(root, name, 1024 * 1024)
            requests.validate(document)
            if name != document['execution'] + '.profile.json' or document['execution'] in executions:
                raise ValueError('Duplicate or mismatched execution profile')
            snapshot = document['profiles']
            executions[document['execution']] = document['measurements']
            for group, categories in snapshot.items():
                if group not in PROFILE_CATEGORIES or not set(categories) <= PROFILE_CATEGORIES[group]:
                    raise ValueError('Invalid diagnostic profile')
                for category, measurements in categories.items():
                    totals = profiles.setdefault(group, {}).setdefault(category, {})
                    for key, number in measurements.items():
                        totals[key] = None if number is None else round(totals.get(key, 0) + number, 6)
    for path in sorted(root.glob('*.summary.json')):
        summary = json.loads(path.read_text())
        values = executions.setdefault(summary['execution'], {})
        for key, count in summary['measurements'].items():
            values[key] = max(values.get(key, 0), count)
    totals = {key: sum(values.get(key, 0) for values in executions.values())
              for key in COUNTER_NAMES}
    totals['logBytes'] = sum(json.loads(path.read_text())['logBytes'] for path in root.glob('*.summary.json'))
    controller = subprocess.run(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], capture_output=True, text=True, check=False, timeout=10)
    revisions = controller.stdout.splitlines() if controller.returncode == 0 else []
    value = {'schema': 2, 'source': os.environ.get('GITHUB_SHA'),
             'controllerSource': revisions[0] if len(revisions) == 2 else None,
             'controllerTree': revisions[1] if len(revisions) == 2 else None,
             'repository': os.environ.get('GITHUB_REPOSITORY'), 'job': os.environ.get('GITHUB_JOB'),
             'run': os.environ.get('GITHUB_RUN_ID'), 'attempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'files': files,
             'receiptCapture': receipts, 'occurrences': occurrences, 'profiles': profiles,
             'requestProfiles': sorted(name for name in files if name.endswith('.profile.json')),
             'nativeStages': sorted(name for name in files if name.endswith('.stage.json')),
             'experiments': {key: os.environ.get(key, 'false') == 'true' for key in
                             ('MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED', 'MAESTRO_PACKET_METADATA_REUSE_ENABLED', 'MAESTRO_DECISION_ONLY_REUSE_ENABLED', 'MAESTRO_PACKET_METADATA_BATCH_ENABLED', 'MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED', 'MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED')},
             'verifiedDestinationsRequired': os.environ.get('PUBLICATION_REQUIRE_VERIFIED') == 'true',
             'measurements': totals, 'httpAttempts': None, 'wireBytes': None,
             'measurementScope': 'Native instrumented processes only; nested phase durations overlap. Captured bytes are retained stdout/stderr and verified downloaded members, not wire bytes. HTTP attempts and wire bytes unavailable. Log bytes count emitted JSON summaries only; completed original job logs are measured separately.'}
    with tempfile.NamedTemporaryFile(dir=root, prefix='.manifest-', delete=False) as stream:
        pending = Path(stream.name)
        try:
            stream.write((json.dumps(value, sort_keys=True, indent=2) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
            if (root / 'manifest.json').is_symlink():
                raise ValueError('Unsafe diagnostic manifest')
            os.replace(pending, root / 'manifest.json')
        finally:
            pending.unlink(missing_ok=True)
    artifacts.verify(root)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--job-log', type=Path)
    parser.add_argument('--job', type=Path)
    args = parser.parse_args()
    if args.verify:
        verified = artifacts.verify(args.verify)
        print(json.dumps({'schema': verified['schema'], 'filesVerified': len(verified['files'])}))
    elif args.job_log and args.job:
        import diagnostic_logs
        print(json.dumps(diagnostic_logs.measure(args.job_log, json.loads(args.job.read_text())), sort_keys=True))
    elif args.job_log or args.job:
        parser.error('--job-log and --job are required together')
    else:
        manifest()
