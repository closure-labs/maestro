# SPDX-License-Identifier: Apache-2.0
"""Bounded request ownership. Contains measurements, never reusable responses."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import copy
import math
import os
import re
import threading

PHASES = {'outside', 'gate', 'policy', 'ledger', 'scans', 'ancestry', 'admission', 'product', 'release', 'refresh'}
STAGES = {'other', 'publication', 'publication-journal', 'publication-assets', 'destinations',
          'handoff', 'packet-materialization', 'admission', 'selection'}
PURPOSES = {'other', 'protected-ref-tree', 'immutable-blob', 'policy-rules', 'proposal-origin',
            'pr-identity-files', 'review-history', 'team-inventory', 'active-membership',
            'repository-permission', 'source-ancestry', 'producer-attestation',
            'journal-read', 'journal-write', 'journal-readback', 'cache-metadata', 'public-read'}
LABELS = {'phase': PHASES, 'stage': STAGES, 'purpose': PURPOSES,
          'authority': {'none', 'current', 'historical'},
          'origin': {'none', 'primary', 'nixos-upstream', 'xo-upstream', 'other'},
          'method': {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'other'},
          'fallback': {'none', '0', '1', '2'},
          'transport': {'none', 'github-api', 'attestation', 'public-http', 'registry', 'other'},
          'inspection': {'none', *(str(i) for i in range(32))}}
DEFAULT = {'phase': 'outside', 'stage': 'other', 'purpose': 'other', 'authority': 'none',
           'origin': 'none', 'method': 'other', 'fallback': 'none', 'transport': 'none', 'inspection': 'none'}
OWNER = ContextVar('request_owner', default=DEFAULT)
INSPECTION = ContextVar('request_inspection', default=None)
ROWS = {}
INSPECTIONS = {}
OVERFLOW = False
LOCK = threading.Lock()
# Fixed dimensions plus a hard cap protect both memory and artifact size.
MAX_ROWS = 512
MAX_INSPECTIONS = 32
COUNTERS = {'apiWrapperInvocations', 'apiTransportInvocations', 'publicTransportInvocations', 'immutableBytesReused'}
TRANSPORT = {'calls', 'wrapperCalls', 'subprocessLaunches', 'explicitRetries', 'capturedBytes',
             'immutableBytesReused', 'elapsedSeconds', 'failures', 'successfulConnections', 'requestStarts',
             'deniedRequestStarts', 'metadataBytes', 'measuredReads', 'unmeasuredReads'}


def enabled():
    return os.environ.get('MAESTRO_CI_DIAGNOSTICS') == 'true'


@contextmanager
def scope(**labels):
    if any(key not in LABELS or value not in LABELS[key] for key, value in labels.items()):
        raise ValueError('Invalid fixed request label')
    token = OWNER.set({**OWNER.get(), **labels})
    try:
        yield
    finally:
        OWNER.reset(token)


def owned(**labels):
    def decorate(function):
        @wraps(function)
        def invoke(*args, **kwargs):
            with scope(**labels):
                return function(*args, **kwargs)
        return invoke
    return decorate


def github_purpose(endpoint, method='GET'):
    # The input is examined transiently. Only a constant label can escape.
    path = endpoint.split('?', 1)[0] if isinstance(endpoint, str) else ''
    if '/contents/publications/' in path or '/git/ref/heads/automation/publication-journals' in path:
        return 'journal-read' if method == 'GET' else 'journal-write'
    if '/rules/branches/' in path or path.endswith('/decision-policy.json'):
        return 'policy-rules'
    if re.fullmatch(r'repos/[^/]+/[^/]+/git/(?:ref/heads/main|trees/[^/]+)', path):
        return 'protected-ref-tree'
    if '/git/blobs/' in path or '/contents/automation/decisions/' in path:
        return 'immutable-blob'
    if re.fullmatch(r'repos/[^/]+/[^/]+/commits', path) or re.fullmatch(r'repos/[^/]+/[^/]+/commits/[^/]+/pulls', path):
        return 'proposal-origin'
    if '/memberships/' in path:
        return 'active-membership'
    if path.startswith('orgs/') and '/teams/' in path:
        return 'team-inventory'
    if '/collaborators/' in path and path.endswith('/permission'):
        return 'repository-permission'
    if re.fullmatch(r'repos/[^/]+/[^/]+/pulls/[0-9]+/reviews', path):
        return 'review-history'
    if '/pulls/' in path or re.fullmatch(r'repos/[^/]+/[^/]+/issues/[0-9]+/timeline', path):
        return 'pr-identity-files'
    if '/compare/' in path:
        return 'source-ancestry'
    if '/actions/' in path or '/attestations/' in path:
        return 'producer-attestation'
    return 'other'


@contextmanager
def github_scope(endpoint, method='GET'):
    purpose = OWNER.get()['purpose']
    if purpose not in ('journal-read', 'journal-write', 'journal-readback'):
        purpose = github_purpose(endpoint, method)
    with scope(purpose=purpose, method=method if method in LABELS['method'] else 'other'):
        yield


def github(function):
    @wraps(function)
    def invoke(endpoint, *args, **kwargs):
        method = kwargs.get('method', args[0] if args else 'GET')
        with github_scope(endpoint, method):
            return function(endpoint, *args, **kwargs)
    return invoke


def process(function):
    @wraps(function)
    def invoke(args, *rest, **kwargs):
        with process_scope(args):
            return function(args, *rest, **kwargs)
    return invoke


@contextmanager
def process_scope(args):
    if len(args) > 1 and str(args[0]).rsplit('/', 1)[-1] == 'gh' and args[1] == 'api':
        endpoint = next((arg for arg in args[2:] if isinstance(arg, str) and arg.startswith(('repos/', 'orgs/'))), '')
        # Do not infer gh's implicit body/GraphQL method from arbitrary fields.
        body_options = ('-f', '-F', '--field', '--raw-field', '--input')
        method = 'other' if 'graphql' in args or any(
            isinstance(arg, str) and (arg in body_options or arg.startswith(('--field=', '--raw-field=', '--input=')))
            for arg in args[2:]) else 'GET'
        for flag in ('--method', '-X'):
            if flag in args and args.index(flag) + 1 < len(args):
                method = args[args.index(flag) + 1]
        with github_scope(endpoint, method):
            yield
    else:
        yield


def public(function):
    @wraps(function)
    def invoke(url, head=False):
        purpose = 'cache-metadata' if INSPECTION.get() is not None else 'public-read'
        with scope(purpose=purpose, method='HEAD' if head else 'GET'):
            return function(url, head=head)
    return invoke


def cache_inspection(function):
    @wraps(function)
    def invoke(*args, **kwargs):
        with inspection():
            return function(*args, **kwargs)
    return invoke


def authority(function):
    @wraps(function)
    def invoke(*args, **kwargs):
        live = kwargs.get('require_live_review', args[7] if len(args) > 7 else True)
        with scope(authority='current' if live else 'historical'):
            return function(*args, **kwargs)
    return invoke


def add(section, name, amount):
    global OVERFLOW
    if not enabled():
        return
    if (section == 'counters' and name not in COUNTERS or
            section == 'transport' and name not in TRANSPORT or section not in ('counters', 'transport')):
        raise ValueError('Invalid request measurement')
    if type(amount) not in (int, float) or not 0 <= amount < 10**20:
        raise ValueError('Invalid request amount')
    owner = OWNER.get()
    key = tuple(owner[key] for key in DEFAULT)
    with LOCK:
        # Overflow remains explicit and additive, never silently drops calls.
        if key not in ROWS and len(ROWS) >= MAX_ROWS:
            OVERFLOW = True
            key = tuple(DEFAULT.values())
        row = ROWS.setdefault(key, {'labels': dict(zip(DEFAULT, key)), 'counters': {}, 'transport': {}})
        values = row[section]
        values[name] = round(values.get(name, 0) + amount, 6) if name == 'elapsedSeconds' else values.get(name, 0) + amount


def transport(**values):
    for name, amount in values.items():
        if amount:
            add('transport', name, amount)


@contextmanager
def inspection():
    global OVERFLOW
    if not enabled():
        yield
        return
    with LOCK:
        number = len(INSPECTIONS)
        if number >= MAX_INSPECTIONS:
            OVERFLOW = True
            number = MAX_INSPECTIONS - 1
        INSPECTIONS.setdefault(number, {'inspection': number, 'distinctPaths': 0, 'requests': {}, 'outcome': 'unknown'})
    token = INSPECTION.set(number)
    try:
        with scope(inspection=str(number)):
            yield
    except BaseException:
        with LOCK:
            INSPECTIONS[number]['outcome'] = 'failure'
        raise
    else:
        with LOCK:
            INSPECTIONS[number]['outcome'] = 'complete'
    finally:
        INSPECTION.reset(token)


def inspected_path():
    if enabled() and INSPECTION.get() is not None:
        with LOCK:
            INSPECTIONS[INSPECTION.get()]['distinctPaths'] += 1


def cache_response(status):
    if not enabled() or INSPECTION.get() is None:
        return
    response = 'unavailable' if status is None else 'found' if status == 200 else 'missing' if status == 404 else 'other-http'
    labels = OWNER.get()
    key = '/'.join((labels['origin'], labels['method'], labels['fallback'], response))
    with LOCK:
        values = INSPECTIONS[INSPECTION.get()]['requests']
        values[key] = values.get(key, 0) + 1


def snapshot():
    with LOCK:
        return {'schema': 1, 'rows': copy.deepcopy([ROWS[key] for key in sorted(ROWS)]),
                'inspections': copy.deepcopy(list(INSPECTIONS.values())),
                'overflowed': OVERFLOW, 'httpAttempts': None, 'wireBytes': None}


def validate(profile):
    """Reconcile one execution exactly; old profiles remain readable."""
    value = profile.get('requests')
    if value is None:
        return
    if (set(value) != {'schema', 'rows', 'inspections', 'overflowed', 'httpAttempts', 'wireBytes'}
            or type(value['schema']) is not int or value['schema'] != 1 or type(value['overflowed']) is not bool
            or value['httpAttempts'] is not None or value['wireBytes'] is not None
            or not isinstance(value['rows'], list) or len(value['rows']) > MAX_ROWS + 1
            or not isinstance(value['inspections'], list) or len(value['inspections']) > MAX_INSPECTIONS):
        raise ValueError('Invalid request attribution')
    keys = set()
    for row in value['rows']:
        if (set(row) != {'labels', 'counters', 'transport'} or set(row['labels']) != set(DEFAULT)
                or any(label not in LABELS[key] for key, label in row['labels'].items())):
            raise ValueError('Invalid request ownership')
        key = tuple(row['labels'][label] for label in DEFAULT)
        if key in keys:
            raise ValueError('Duplicate request ownership')
        keys.add(key)
        for section, names in (('counters', COUNTERS), ('transport', TRANSPORT)):
            if (not set(row[section]) <= names or any(
                    type(number) not in ((int, float) if section == 'transport' and name == 'elapsedSeconds' else (int,))
                    or not math.isfinite(number) or not 0 <= number < 10**25 for name, number in row[section].items())):
                raise ValueError('Invalid request totals')
    for name in COUNTERS:
        if sum(row['counters'].get(name, 0) for row in value['rows']) != profile['measurements'].get(name, 0):
            raise ValueError('Request counters do not reconcile')
    # An overflow row retains additive totals but deliberately loses dimensions.
    # It cannot support per-purpose conclusions; the artifact states this.
    for name in TRANSPORT:
        measured = sum(row['transport'].get(name, 0) for row in value['rows'])
        total = sum(row.get(name, 0) for row in profile['profiles'].get('transport', {}).values())
        if not math.isclose(measured, total, rel_tol=0, abs_tol=0.0001 if name == 'elapsedSeconds' else 0):
            raise ValueError('Request transport totals do not reconcile')
    if not value['overflowed']:
        for category, totals in profile['profiles'].get('transport', {}).items():
            rows = [row for row in value['rows'] if row['labels']['transport'] == category]
            for name in TRANSPORT:
                measured = sum(row['transport'].get(name, 0) for row in rows)
                if not math.isclose(measured, totals.get(name, 0), rel_tol=0, abs_tol=0.0001 if name == 'elapsedSeconds' else 0):
                    raise ValueError('Request transport measurements do not reconcile')
    response_keys = {'/'.join((origin, 'GET', depth, status))
                     for origin in ('primary', 'nixos-upstream', 'xo-upstream')
                     for depth in ('0', '1', '2') for status in ('found', 'missing', 'other-http', 'unavailable')}
    for index, inspection in enumerate(value['inspections']):
        if (set(inspection) != {'inspection', 'distinctPaths', 'requests', 'outcome'}
                or type(inspection['inspection']) is not int or inspection['inspection'] != index or type(inspection['distinctPaths']) is not int
                or not 0 <= inspection['distinctPaths'] < 10**20
                or inspection['outcome'] not in ('unknown', 'complete', 'failure')
                or not set(inspection['requests']) <= response_keys
                or any(type(number) is not int or not 0 <= number < 10**20 for number in inspection['requests'].values())):
            raise ValueError('Invalid inspection attribution')
