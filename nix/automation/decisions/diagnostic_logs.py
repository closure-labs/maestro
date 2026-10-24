# SPDX-License-Identifier: Apache-2.0
"""Offline byte attribution from an original completed job log and job metadata."""
import datetime as dt
import hashlib
import re

CATEGORIES = ('runner-monitoring', 'cleanup', 'native', 'artifacts', 'setup', 'other', 'unattributed')
NATIVE = {
    'Download completed protected candidate data', 'Verify live admission and exact distribution roots',
    'Reserve exact official cache recovery identity', 'Inspect current public cache before closure materialization',
    'Restore authenticated qualified Nix closures without builders',
    'Verify pinned upstream handoff against actual appliance exposure', 'Publish verified realized closures',
    'Record freshly verified cache destination', 'Inspect exact rolling FlakeHub destination',
    'Recheck live admission before FlakeHub publication', 'Publish exact admitted rolling revision',
    'Verify published rolling FlakeHub revision', 'Record freshly verified rolling FlakeHub destination',
    'Retain immutable decision byte reuse observations', 'Bind publication diagnostics to this execution',
}


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', value):
        raise ValueError('Invalid completed job timestamp')
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def category(name):
    if name in ('Pre Monitor hosted runner', 'Monitor hosted runner', 'Post Monitor hosted runner'):
        return 'runner-monitoring'
    if name.startswith('Post ') or name == 'Complete job':
        return 'cleanup'
    if name in NATIVE:
        return 'native'
    if name == 'Retain complete publication diagnostics':
        return 'artifacts'
    if name in ('Set up job', 'Checkout trusted controller', 'Set up Nix',
                'Create repository-scoped authority and journal token', 'Mint independently scoped upstream authority reader'):
        return 'setup'
    return 'other'


def measure(path, job):
    if job.get('status') != 'completed' or not job.get('completed_at'):
        raise ValueError('Original completed job metadata required')
    start, end = timestamp(job['started_at']), timestamp(job['completed_at'])
    if end < start:
        raise ValueError('Invalid completed job interval')
    intervals = []
    for step in job['steps']:
        if step.get('started_at') and step.get('completed_at') and step.get('conclusion') != 'skipped':
            a, b = timestamp(step['started_at']), timestamp(step['completed_at'])
            if b < a:
                raise ValueError('Invalid completed step interval')
            intervals.append((a, b, category(step['name'])))
    counts = dict.fromkeys(CATEGORIES, 0)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for line in stream:
            digest.update(line)
            selected = 'unattributed'
            try:
                moment = timestamp(line.split(b' ', 1)[0].decode('ascii'))
                matches = [label for a, b, label in intervals if a <= moment < b]
                if len(matches) == 1:
                    selected = matches[0]
            except (ValueError, UnicodeError):
                pass
            counts[selected] += len(line)
    return {'schema': 1, 'rawJobLogBytes': sum(counts.values()), 'rawJobLogSha256': digest.hexdigest(),
            'bytesByCategory': counts, 'jobSeconds': (end - start).total_seconds(),
            'scope': 'Original completed job log, including timestamps and line endings. Ambiguous or uncovered timestamps are unattributed; step times have API precision. No raw log content retained.'}
