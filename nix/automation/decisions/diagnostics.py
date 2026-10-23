# SPDX-License-Identifier: Apache-2.0
"""Execution evidence and bounded public summaries; never authority or a retry."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid

STARTED = time.monotonic()
EXECUTION = uuid.uuid4().hex
COUNTERS = {}
LOCK = threading.Lock()
COUNTER_NAMES = ('gateInvocations', 'apiWrapperInvocations', 'apiTransportInvocations',
                 'publicTransportInvocations', 'immutableBytesReused')
KINDS = {'admission', 'publication', 'publication-journal', 'publication-assets', 'destinations', 'gate'}


def enabled():
    return os.environ.get('MAESTRO_CI_DIAGNOSTICS') == 'true'


def count(name, amount=1):
    if enabled():
        with LOCK:
            COUNTERS[name] = COUNTERS.get(name, 0) + amount


def directory():
    root = Path(os.environ['RUNNER_TEMP']) / 'publication-diagnostics'
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def identity(value):
    return value if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value) else None


def bounded_count(value):
    return value if type(value) is int and 0 <= value < 10**20 else None


def collection_count(result, collection, fallback):
    value = result.get(collection)
    return len(value) if isinstance(value, (list, dict)) else bounded_count(result.get(fallback))


def record(result, kind=None, logged=True):
    kind = kind or Path(os.sys.argv[0]).stem
    if not enabled() or kind not in KINDS:
        return None
    raw = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    digest = hashlib.sha256(raw).hexdigest()
    name = uuid.uuid4().hex
    (directory() / (name + '.result.json')).write_bytes(raw)
    outcome = result.get('status')
    if outcome not in ('allowed', 'covered', 'blocked', 'verified', 'partial', 'missing', 'conflict', 'unavailable', 'complete', 'pending', 'published', 'staged'):
        outcome = 'completed'
    producer = result.get('producer', {})
    if not isinstance(producer, dict):
        producer = {}
    summary = {'schema': 1, 'execution': EXECUTION, 'kind': kind, 'status': outcome,
               'productHash': identity(result.get('productHash')),
               'proposalHash': identity(result.get('proposalHash')),
               'decisionHash': identity(result.get('decisionHash')),
               'producerRevision': identity(producer.get('revision')),
               'producerRun': bounded_count(producer.get('runId')),
               'producerAttempt': bounded_count(producer.get('runAttempt')),
               'rootCount': collection_count(result, 'expected', 'rootCount'),
               'findingCount': collection_count(result, 'findings', 'findingCount'),
               'elapsedSeconds': round(time.monotonic() - STARTED, 3), 'evidenceDigest': digest,
               'measurements': {key: COUNTERS.get(key, 0) for key in COUNTER_NAMES},
               # gh and curl can retry internally. Their process invocations
               # must never be presented as a count of actual HTTP attempts.
               'httpAttempts': None, 'logBytes': 0}
    value = json.dumps(summary, sort_keys=True, separators=(',', ':')) + '\n'
    assert len(value.encode()) <= 4096
    while logged and summary['logBytes'] != len(value.encode()):
        summary['logBytes'] = len(value.encode())
        value = json.dumps(summary, sort_keys=True, separators=(',', ':')) + '\n'
    assert len(value.encode()) <= 4096
    (directory() / (name + '.summary.json')).write_text(value)
    return value


def manifest():
    root = directory()
    files = {path.name: {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size}
             for path in sorted(root.iterdir()) if path.is_file() and path.name != 'manifest.json'}
    executions = {}
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
    value = {'schema': 1, 'source': os.environ.get('GITHUB_SHA'),
             'controllerSource': revisions[0] if len(revisions) == 2 else None,
             'controllerTree': revisions[1] if len(revisions) == 2 else None,
             'repository': os.environ.get('GITHUB_REPOSITORY'), 'job': os.environ.get('GITHUB_JOB'),
             'run': os.environ.get('GITHUB_RUN_ID'), 'attempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'files': files,
             'measurements': totals, 'httpAttempts': None,
             'measurementScope': 'Native gates and instrumented API/public transport wrappers only; HTTP attempts unavailable. Log bytes count emitted JSON summaries only.'}
    (root / 'manifest.json').write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    manifest()
