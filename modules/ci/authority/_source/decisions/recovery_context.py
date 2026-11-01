# SPDX-License-Identifier: Apache-2.0
"""Bounded invocation-local historical proofs and locator-only recovery receipts."""
from collections.abc import MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from functools import wraps
import hashlib
import json
import os
import re
from pathlib import Path
import tempfile
import time
import threading
import uuid

import common
import decision_authority as authority
import decision_packets as packets
from security_decisions import canonical_hash

MAX_PROOFS = 256
MAX_RESULT_BYTES = 4096
MAX_RECEIPT_BYTES = 32768
MAX_PASSES = 16
MAX_EVENTS = 256
_CURRENT = ContextVar('security_recovery_invocation', default=None)
PURPOSES = {'reconcile', 'authority-check', 'packet-validation', 'recovery-validation', 'proposal-validation', 'proposal-write'}
PHASES = {'snapshot-observation', 'ledger-observation', 'policy-observation', 'rules-observation', 'final-main-observation', 'historical-provenance', 'live-parents', 'historical-packets',
          'snapshot-verified', 'evidence-verified', 'packet-push-requested', 'packet-pushed',
          'proposal-prepared', 'proposal-verified', 'pre-write-verified', 'proposal-write-requested', 'draft-created', 'proposal-found'}


def trust_version():
    root = Path(__file__).parent
    return canonical_hash({
        'source': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob('*.py'))},
        'team': [authority.APPROVER_ORG, authority.APPROVER_TEAM, authority.APPROVER_TEAM_ID],
        'registry': [packets.REGISTRY, packets.REFERENCE.pattern, packets.TYPE],
        'githubHost': os.environ.get('GH_HOST', 'github.com'),
        'githubServer': os.environ.get('GITHUB_SERVER_URL', 'https://github.com')})


class NoDocuments(MutableMapping):
    """Never retain large parsed documents or mutable API observations."""
    def __setitem__(self, key, value):
        pass

    def __getitem__(self, key):
        raise KeyError(key)

    def __delitem__(self, key):
        raise KeyError(key)

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0


class HistoricalResults(MutableMapping):
    def __init__(self, owner):
        self.owner, self._values = owner, {}

    def __contains__(self, key):
        hit = key in self._values
        self.owner.counts['historicalHits' if hit else 'historicalMisses'] += 1
        return hit

    def __getitem__(self, key):
        value, digest = self._values[key]
        if canonical_hash(value) != digest:
            self.owner.abort('Recovery historical proof cache mutated')
        return deepcopy(value)

    def __setitem__(self, key, value):
        common.require(len(self._values) < MAX_PROOFS or key in self._values, 'Recovery historical proof budget exceeded')
        common.require(isinstance(value, dict) and value.get('status') == 'historical-provenance'
                       and value.get('reviewer') is None and value.get('reviewId') is None
                       and value.get('permissionPolicy') == 'immutable-bot-merge-provenance'
                       and value.get('proposalHash') == key
                       and value.get('repository') == self.owner.binding[0]
                       and authority.SHA.fullmatch(value.get('reviewedHead', ''))
                       and authority.SHA.fullmatch(value.get('mergeCommit', '')),
                       'Only immutable historical provenance may be retained')
        common.require(len(json.dumps(value).encode()) <= MAX_RESULT_BYTES, 'Recovery historical proof exceeds bound')
        self._values[key] = deepcopy(value), canonical_hash(value)
        self.owner.counts['historicalChecks'] += 1

    def __delitem__(self, key):
        del self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def clear(self):
        self._values.clear()


class Origins(MutableMapping):
    def __init__(self):
        self._values = {}

    def __getitem__(self, key):
        return self._values[key]

    def __setitem__(self, key, value):
        common.require(len(self) < MAX_PROOFS or key in self, 'Recovery historical proof budget exceeded')
        common.require(type(value) is int and 0 < value < 2**63, 'Invalid historical origin')
        self._values[key] = value

    def __delitem__(self, key):
        del self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def clear(self):
        self._values.clear()


class Invocation:
    def __init__(self, purpose):
        common.require(purpose in PURPOSES, 'Invalid recovery invocation purpose')
        self.owner = os.getpid(), threading.get_ident()
        self.purpose, self.identifier = purpose, uuid.uuid4().hex
        self.started, self.binding, self.revision, self.closed = time.monotonic(), None, None, False
        self.history, self.origins = HistoricalResults(self), Origins()
        self.documents, self.blobs, self.members = NoDocuments(), NoDocuments(), None
        self.counts = dict.fromkeys(('historicalChecks', 'historicalHits', 'historicalMisses', 'validations',
                                    'ledgerReads', 'policyReads', 'ruleChecks', 'liveParents', 'packetProofs', 'mainReads'), 0)
        self.receipt, self.events = None, 0
        self.value = {'schema': 1, 'invocation': self.identifier, 'purpose': purpose,
                      'status': 'running', 'authorization': False, 'phase': 'snapshot-observation'}

    @property
    def members(self):
        return None

    @members.setter
    def members(self, value):
        common.require(value is None, 'Recovery cannot retain membership')

    def abort(self, message):
        self.close('failed')
        raise ValueError(message)

    def check_owner(self):
        common.require(self.owner == (os.getpid(), threading.get_ident()), 'Recovery invocation owner changed')

    def bind(self, cfg, request, revision, records):
        self.check_owner()
        current = (cfg['repository'], revision, canonical_hash(records), canonical_hash(cfg),
                   canonical_hash(request), trust_version())
        common.require(not self.closed, 'Recovery invocation already closed')
        if self.binding is None:
            self.binding, self.revision = current, revision
        elif self.binding != current:
            self.close('failed')
            raise ValueError('Recovery immutable proof binding changed')
        common.require(sum(p['kind'] in ('security-findings', 'security-revocation') for p in records.values()) <= MAX_PROOFS,
                       'Recovery historical proof budget exceeded')
        self.value['binding'] = dict(zip(('repository', 'mainRevision', 'graphHash', 'policyHash', 'requestHash', 'trustHash'), current))
        self.value['parents'] = list(request['parents'])

    def repository(self, repository):
        self.check_owner()
        if self.closed or self.binding is None or self.binding[0] != repository or self.binding[-1] != trust_version():
            self.abort('Recovery historical trust binding changed')

    def phase(self, phase, **locators):
        self.check_owner()
        common.require(not self.closed, 'Recovery invocation already closed')
        common.require(phase in PHASES and set(locators) <= {'packet', 'proposalHash', 'head', 'pullRequest', 'proofHash'},
                       'Invalid recovery receipt phase')
        previous = self.value['phase']
        self.value['phase'] = phase
        for key, value in locators.items():
            if key in ('proposalHash', 'proofHash'):
                common.require(isinstance(value, str) and common.HASH.fullmatch(value), 'Invalid recovery receipt hash')
            elif key == 'head':
                common.require(isinstance(value, str) and authority.SHA.fullmatch(value), 'Invalid recovery receipt head')
            elif key == 'pullRequest':
                common.require(type(value) is int and value > 0, 'Invalid recovery receipt PR')
            elif key == 'packet':
                value = packet_locator(value)
            self.value[key] = value
        self.flush(force=True)
        if previous != phase or phase in ('packet-push-requested', 'packet-pushed', 'draft-created'):
            self.events += 1
            common.require(self.events <= MAX_EVENTS, 'Recovery progress budget exceeded')
            summary = os.environ.get('GITHUB_STEP_SUMMARY')
            if summary:
                with Path(summary).open('a') as stream:
                    stream.write(f'- Security recovery {self.identifier}: {phase}; historical checks {self.counts["historicalChecks"]}; '
                                 f'hits {self.counts["historicalHits"]}; live parents {self.counts["liveParents"]}; '
                                 f'packet proofs {self.counts["packetProofs"]}.\n')
            print(json.dumps({'schema': 1, 'kind': 'security-recovery-progress', 'invocation': self.identifier,
                              'phase': phase, 'counts': self.counts}, sort_keys=True), flush=True)

    def flush(self, force=False):
        if self.receipt is None:
            if not force and self.binding is None:
                return
            root = Path(tempfile.mkdtemp(prefix='security-recovery-', dir=os.environ.get('RUNNER_TEMP')))
            self.receipt = root / 'receipt.json'
        self.value['counts'] = dict(self.counts)
        self.value['elapsedSeconds'] = round(time.monotonic() - self.started, 3)
        raw = (json.dumps(self.value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        common.require(len(raw) <= MAX_RECEIPT_BYTES, 'Recovery receipt exceeds bound')
        common.require(not self.receipt.parent.is_symlink() and not self.receipt.is_symlink(), 'Unsafe recovery receipt')
        with tempfile.NamedTemporaryFile(dir=self.receipt.parent, delete=False) as stream:
            name = stream.name
            try:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                os.replace(name, self.receipt)
            finally:
                Path(name).unlink(missing_ok=True)

    def close(self, status):
        if self.closed:
            return
        common.require(status in ('completed', 'failed'), 'Invalid recovery receipt status')
        self.value['status'] = status
        try:
            self.flush()
        finally:
            self.closed = True
            self.history.clear()
            self.origins.clear()
            self.documents.clear()
            self.blobs.clear()


def packet_locator(packet):
    common.require(isinstance(packet, dict) and common.HASH.fullmatch(packet.get('sha256', '')), 'Invalid recovery packet receipt')
    result = {'sha256': packet['sha256'], 'tag': packets.REGISTRY + ':packet-' + packet['sha256']}
    if 'reference' in packet:
        common.require(packets.REFERENCE.fullmatch(packet['reference']), 'Invalid recovery packet reference')
        result['reference'] = packet['reference']
    producer = packet.get('producer', {})
    common.require(isinstance(producer, dict) and authority.REPOSITORY.fullmatch(producer.get('repository', ''))
                   and all(authority.SHA.fullmatch(producer.get(k, '')) for k in ('revision', 'sourceRevision'))
                   and all(type(producer.get(k)) is int and producer[k] > 0 for k in ('runId', 'runAttempt'))
                   and all(isinstance(producer.get(k), str) and re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', producer[k])
                           for k in ('workflow',) + (('signerWorkflow',) if 'signerWorkflow' in producer else ())),
                   'Invalid recovery receipt producer')
    result['producer'] = {k: producer[k] for k in ('repository', 'revision', 'sourceRevision', 'runId', 'runAttempt', 'workflow', 'signerWorkflow') if k in producer}
    return result


def current():
    return _CURRENT.get()


@contextmanager
def lifetime(purpose, *, reuse=False):
    previous = current()
    if reuse and previous is not None:
        previous.check_owner()
        common.require(not previous.closed, 'Recovery invocation already closed')
        yield previous
        return
    state = Invocation(purpose)
    token = _CURRENT.set(state)
    try:
        yield state
    except BaseException:
        state.close('failed')
        raise
    else:
        state.close('completed')
    finally:
        _CURRENT.reset(token)


def scoped(purpose, *, reuse=True, when=None):
    def decorate(function):
        @wraps(function)
        def invoke(*args, **kwargs):
            if when is not None and not when(*args, **kwargs):
                return function(*args, **kwargs)
            with lifetime(purpose, reuse=reuse):
                return function(*args, **kwargs)
        return invoke
    return decorate
