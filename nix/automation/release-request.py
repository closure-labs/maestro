#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded release-request journal and protected-main continuation resolver."""
import base64
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

TTL = dt.timedelta(hours=48)
NOW = dt.datetime.now(dt.timezone.utc)
REPO = os.environ.get('GITHUB_REPOSITORY', '')
SHA = re.compile(r'[0-9a-f]{40}')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+')
MARKER = re.compile(r'Maestro release request ([1-9][0-9]*)')
RUN_ID = re.compile(r'[1-9][0-9]*')


def command(*args, timeout=None):
    return subprocess.check_output(args, text=True, timeout=timeout).strip()


def api(path, timeout=None):
    return json.loads(command('gh', 'api', f'repos/{REPO}/{path}', timeout=timeout))


def timestamp(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def retired(identity):
    configured = json.loads(os.environ.get('MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS', '[]'))
    require(type(configured) is list and len(configured) <= 16 and
            all(type(value) is int and value > 0 for value in configured) and
            len(set(configured)) == len(configured), 'Invalid retired release request IDs')
    return identity in configured


def input_run(key):
    value = os.environ.get(key, '')
    require(RUN_ID.fullmatch(value), 'Invalid release run ID: ' + key)
    return api(f'actions/runs/{int(value)}')


def completion(run, deadline):
    for attempt in range(25):
        if run['status'] == 'completed':
            return run
        remaining = deadline - time.monotonic()
        require(attempt < 24 and remaining > 0, 'Release completion signal timed out after 120 seconds')
        time.sleep(min(5, remaining))
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Release completion signal timed out after 120 seconds')
        run = api(f"actions/runs/{run['id']}", timeout=remaining)
        require(time.monotonic() <= deadline, 'Release completion signal timed out after 120 seconds')


def emit(**values):
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        for key, value in values.items():
            output.write(f'{key}={str(value).lower() if isinstance(value, bool) else value}\n')


def recent(workflow):
    # Fail closed rather than miss an active request when the bounded window
    # overflows. Routine older runs are irrelevant to a 48-hour journal.
    result = []
    for page in range(1, 4):
        runs = api(f'actions/workflows/{workflow}/runs?event=workflow_dispatch&branch=main&per_page=100&page={page}')['workflow_runs']
        result.extend(run for run in runs if timestamp(run['created_at']) >= NOW - TTL)
        if len(runs) < 100 or timestamp(runs[-1]['created_at']) < NOW - TTL:
            return result
    raise ValueError('Release request lookup exceeded the bounded 48-hour window')


def trusted(run, workflow):
    require(run['repository']['full_name'] == REPO and run['head_repository']['full_name'] == REPO,
            'Cross-repository release run')
    require(run['event'] == 'workflow_dispatch' and run['head_branch'] == 'main' and
            run['path'] == f'.github/workflows/{workflow}' and SHA.fullmatch(run['head_sha']),
            'Release run lacks protected-main workflow identity')


def journal(origin):
    artifacts = api(f"actions/runs/{origin['id']}/artifacts?per_page=100")
    require(artifacts['total_count'] <= 100, 'Release artifact lookup overflow')
    matches = [a for a in artifacts['artifacts'] if a['name'] == 'maestro-release-request']
    if not matches:
        return None
    require(len(matches) == 1 and not matches[0]['expired'], 'Expired or ambiguous release request artifact')
    with tempfile.TemporaryDirectory(prefix='maestro-release-request-') as directory:
        command('gh', 'run', 'download', str(origin['id']), '--repo', REPO,
                '--name', 'maestro-release-request', '--dir', directory)
        request = json.loads((Path(directory) / 'maestro-release-request.json').read_text())
    require(set(request) == {'schema_version', 'repository', 'request_run_id', 'source_sha', 'tag', 'version', 'created_at', 'expires_at'},
            'Invalid release request fields')
    require(type(request['schema_version']) is int and request['schema_version'] == 1 and request['repository'] == REPO and
            type(request['request_run_id']) is int and request['request_run_id'] == origin['id'], 'Release request origin mismatch')
    require(SHA.fullmatch(request['source_sha']) and VERSION.fullmatch(request['version']) and
            request['tag'] == 'v' + request['version'], 'Invalid release request source or version')
    created, expires = timestamp(request['created_at']), timestamp(request['expires_at'])
    require(timestamp(origin['created_at']) <= created <= NOW and expires == timestamp(origin['created_at']) + TTL,
            'Invalid release request lifetime')
    return request


def candidate(request):
    matches = [run for run in recent('ci.yml') if run['display_title'] == f"Maestro release request {request['request_run_id']}"]
    require(len(matches) <= 1, 'Ambiguous release qualification request')
    if not matches:
        return None
    run = matches[0]
    trusted(run, 'ci.yml')
    require(run['head_sha'] == request['source_sha'], 'Candidate source differs from release request')
    return run


def published(request):
    # API errors other than absence must fail, never turn into permission to
    # overwrite a release. Resolve lightweight and annotated tags identically.
    response = subprocess.run(['gh', 'api', f"repos/{REPO}/releases/tags/{request['tag']}"], text=True, capture_output=True)
    if response.returncode:
        require('HTTP 404' in response.stderr, 'Unable to establish release publication state')
        return False
    release = json.loads(response.stdout)
    if release['draft']:
        return False
    commit = api(f"commits/{request['tag']}")['sha']
    require(commit == request['source_sha'], 'Published release tag has a different source')
    return True


def validate(request, origin, run):
    trusted(origin, 'release.yml')
    require(origin['status'] == 'completed' and origin['conclusion'] == 'success', 'Origin release request did not succeed')
    require(NOW < timestamp(request['expires_at']), 'Release request expired')
    trusted(run, 'ci.yml')
    require(run['head_sha'] == request['source_sha'] and run['display_title'] == f"Maestro release request {origin['id']}" and
            run['status'] == 'completed' and run['conclusion'] == 'success', 'Qualification is not the successful exact requested candidate')
    for base, head in [(origin['head_sha'], request['source_sha']), (request['source_sha'], 'main')]:
        require(api(f'compare/{base}...{head}')['status'] in ('ahead', 'identical'), 'Release source is outside protected-main ancestry')
    version = api(f"contents/VERSION?ref={request['source_sha']}")
    require(base64.b64decode(version['content']).decode().strip() == request['version'], 'Release source VERSION mismatch')


def create():
    require(os.environ.get('MAESTRO_RELEASE_CONTINUATION_ENABLED') == 'true', 'Event continuation pilot is disabled')
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch',
            'Release requests require a main dispatch')
    source, version, tag = (os.environ[key] for key in ('SOURCE_SHA', 'RELEASE_VERSION', 'RELEASE_TAG'))
    require(SHA.fullmatch(source) and VERSION.fullmatch(version) and tag == 'v' + version, 'Invalid release request identity')
    origin = api(f"actions/runs/{int(os.environ['GITHUB_RUN_ID'])}")
    trusted(origin, 'release.yml')
    expires = timestamp(origin['created_at']) + TTL
    require(NOW < expires, 'Release request origin expired')
    request = dict(schema_version=1, repository=REPO, request_run_id=origin['id'],
                   source_sha=source, version=version, tag=tag, created_at=NOW.isoformat(), expires_at=expires.isoformat())
    Path('maestro-release-request.json').write_text(json.dumps(request, sort_keys=True) + '\n')


def pending():
    # Called before any version mutation, including the synchronous path.
    require(os.environ.get('EVENT_CONTINUATION', 'false') in ('true', 'false'), 'Invalid continuation flag')
    if os.environ.get('EVENT_CONTINUATION') == 'true':
        require(os.environ.get('MAESTRO_RELEASE_CONTINUATION_ENABLED') == 'true', 'Event continuation pilot is disabled')
    own = int(os.environ.get('GITHUB_RUN_ID', '0'))
    retired(own)  # Validate configuration even when there are no older runs.
    for origin in recent('release.yml'):
        if origin['id'] == own:
            continue
        trusted(origin, 'release.yml')
        if retired(origin['id']):
            continue
        require(origin['status'] == 'completed', 'Another release request is still active')
        if origin['conclusion'] != 'success':
            continue
        request = journal(origin)
        if request is None or NOW >= timestamp(request['expires_at']):
            continue
        run = candidate(request)
        if run is not None and run['status'] == 'completed' and run['conclusion'] != 'success':
            continue
        require(published(request), 'An unexpired release candidate is awaiting continuation')
        # VERSION advancement is also required before a new preparation.
        current = api('contents/VERSION?ref=main')
        require(base64.b64decode(current['content']).decode().strip() != request['version'], 'Published release still awaits version advancement')


def signal():
    require(os.environ.get('MAESTRO_RELEASE_CONTINUATION_ENABLED') == 'true', 'Event continuation pilot is disabled')
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch',
            'Release completion signals require a main dispatch')
    origin, run = input_run('RELEASE_REQUEST_RUN_ID'), input_run('GITHUB_RUN_ID')
    trusted(origin, 'release.yml')
    trusted(run, 'ci.yml')
    require(not retired(origin['id']), 'Release request was explicitly retired')
    request = journal(origin)
    require(request is not None and NOW < timestamp(request['expires_at']) and
            (origin['status'] == 'in_progress' or
             (origin['status'] == 'completed' and origin['conclusion'] == 'success')), 'Release request is not active')
    require(run['head_sha'] == request['source_sha'] == os.environ.get('GITHUB_SHA') and
            run['display_title'] == f"Maestro release request {origin['id']}", 'Completion signal candidate identity mismatch')
    jobs = api(f"actions/runs/{run['id']}/jobs?per_page=100")
    require(jobs['total_count'] <= 100, 'Release candidate job lookup overflow')
    verdicts = [job for job in jobs['jobs'] if job['name'] == 'Required CI verdict']
    require(len(verdicts) == 1 and verdicts[0]['status'] == 'completed' and verdicts[0]['conclusion'] == 'success',
            'Release candidate verdict has not succeeded')
    command('gh', 'workflow', 'run', 'release-continuation.yml', '--repo', REPO, '--ref', 'main',
            '-f', f"release_request_run_id={origin['id']}", '-f', f"release_candidate_run_id={run['id']}")


def resolve():
    require(os.environ.get('MAESTRO_RELEASE_CONTINUATION_ENABLED') == 'true', 'Event continuation pilot is disabled')
    explicit = bool(os.environ.get('RELEASE_REQUEST_RUN_ID') or os.environ.get('RELEASE_CANDIDATE_RUN_ID'))
    if explicit:
        require(os.environ.get('GITHUB_REF') == 'refs/heads/main' and
                os.environ.get('GITHUB_EVENT_NAME') in ('workflow_dispatch', 'workflow_run'),
                'Explicit continuation requires protected main')
        origin, run = input_run('RELEASE_REQUEST_RUN_ID'), input_run('RELEASE_CANDIDATE_RUN_ID')
    else:
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())['workflow_run']
        # workflow_run is an untrusted trigger: fetch current authoritative
        # metadata instead of passing trigger fields to shell commands.
        trigger = api(f"actions/runs/{int(event['id'])}")
        if trigger['path'] == '.github/workflows/ci.yml':
            marker = MARKER.fullmatch(trigger['display_title'])
            if not marker:
                emit(ready=False)
                return
            origin = api(f'actions/runs/{int(marker[1])}')
            run = trigger
        elif trigger['path'] == '.github/workflows/release.yml' and trigger['event'] == 'workflow_dispatch':
            origin, run = trigger, None
        else:
            emit(ready=False)
            return
    trusted(origin, 'release.yml')
    if retired(origin['id']):
        emit(ready=False)
        return
    request = journal(origin)
    if request is None or NOW >= timestamp(request['expires_at']):
        emit(ready=False)
        return
    run = run or candidate(request)
    if explicit and run is not None:
        trusted(run, 'ci.yml')
        require(run['head_sha'] == request['source_sha'] and
                run['display_title'] == f"Maestro release request {origin['id']}", 'Continuation candidate identity mismatch')
        # The signal job dispatches before its own run has fully completed.
        # Bound this short scheduling race; never wait for qualification here.
        deadline = time.monotonic() + 120
        origin = completion(origin, deadline)
        if origin['conclusion'] == 'success':
            run = completion(run, deadline)
    if (origin['status'] != 'completed' or origin['conclusion'] != 'success' or
            run is None or run['status'] != 'completed' or run['conclusion'] != 'success'):
        emit(ready=False)
        return
    validate(request, origin, run)
    already_published = published(request)
    if already_published:
        main_version = api('contents/VERSION?ref=main')
        if base64.b64decode(main_version['content']).decode().strip() != request['version']:
            # An earlier continuation already advanced VERSION, or a later
            # release is in progress. Never spawn a stale advancement job.
            emit(ready=False)
            return
    emit(ready=True, run_id=run['id'], source_sha=request['source_sha'], tag=request['tag'],
         version=request['version'], request_run_id=origin['id'], already_published=already_published)


if __name__ == '__main__':
    try:
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', REPO), 'Invalid repository identity')
        {'create': create, 'pending': pending, 'signal': signal, 'resolve': resolve}[sys.argv[1]]()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, IndexError) as error:
        print(f'Release request rejected: {error}', file=sys.stderr)
        sys.exit(1)
