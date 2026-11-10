#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reuse only a successful, recent, exact-commit merge-queue audit on main.

This transports verified validation evidence, not executable store paths or
release/approval authority. A cache miss always falls back to a complete audit.
The normal graph-reference step still checks every output against a freshly
evaluated candidate graph and creates this run's own reference.
"""
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import time
import subprocess
import tempfile
import zipfile

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_MEMBER = 4 * 1024 * 1024
MAX_AGE = dt.timedelta(hours=24)
FILES = ('audit.json', 'timings.json', 'reference.json')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stamp(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def positive(value):
    return type(value) is int and value > 0


def eligible(env):
    return (env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_EVENT_NAME') == 'push'
            and env.get('GITHUB_REF') == 'refs/heads/main'
            and re.fullmatch(r'[a-f0-9]{40}', env.get('GITHUB_SHA', ''))
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', env.get('GITHUB_REPOSITORY', ''))
            and bool(env.get('GH_TOKEN')))


def verify_run(run, repository, sha, now):
    require(run.get('repository', {}).get('full_name') == repository
            and run.get('head_repository', {}).get('full_name') == repository,
            'Different source repository')
    require(run.get('event') == 'merge_group' and run.get('head_sha') == sha
            and run.get('path') == '.github/workflows/ci.yml'
            and run.get('status') == 'completed' and run.get('conclusion') == 'success',
            'Not a successful exact-commit queue CI')
    require(positive(run.get('id')) and positive(run.get('run_attempt')), 'Missing exact attempt')
    require(dt.timedelta(0) <= now - stamp(run['updated_at']) <= MAX_AGE,
            'Stale or future source run')


def verify_jobs(jobs, attempt):
    # The overlap workflow may split execution and binding across two jobs.
    required_steps = {'Validate repository', 'Bind complete audit reference to this candidate and attempt'}
    successes = set()
    for job in jobs:
        require(job.get('run_attempt') == attempt, 'Changed job attempt')
        if job.get('name') in ('Repository checks', 'Execute repository validation'):
            require(job.get('conclusion') == 'success', 'Source audit did not succeed')
            successes.update(step['name'] for step in job.get('steps', [])
                             if step.get('conclusion') == 'success')
    require(required_steps <= successes, 'Missing complete audit execution or binding')
    require(any(job.get('name') == 'Required CI verdict' and job.get('conclusion') == 'success'
                for job in jobs), 'Missing successful required verdict')


def verify_artifact(artifact, run, repository, sha, now):
    require(artifact.get('name') == 'maestro-audit-audit' and artifact.get('expired') is False
            and positive(artifact.get('id')) and positive(artifact.get('size_in_bytes'))
            and artifact['size_in_bytes'] <= MAX_ARCHIVE, 'Missing or oversized audit artifact')
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', artifact.get('digest', '')), 'Missing artifact digest')
    binding = artifact.get('workflow_run', {})
    require(binding.get('id') == run['id'] and binding.get('head_sha') == sha
            and binding.get('repository_id') == run['repository']['id']
            and binding.get('head_repository_id') == run['repository']['id'], 'Artifact producer mismatch')
    require(stamp(artifact['created_at']) >= stamp(run['run_started_at'])
            and dt.timedelta(0) <= now - stamp(artifact['created_at']) <= MAX_AGE
            and stamp(artifact['expires_at']) > now, 'Artifact is from an old attempt or expired')


def unpack(archive, artifact, run, repository, sha):
    require(len(archive) <= MAX_ARCHIVE and 'sha256:' + digest(archive) == artifact['digest'],
            'Audit archive digest mismatch')
    values = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        for name in FILES:
            matches = [entry for entry in zipped.infolist() if entry.filename == name]
            require(len(matches) == 1 and matches[0].file_size <= MAX_MEMBER
                    and not matches[0].is_dir(), 'Missing, duplicate or oversized audit member')
            values[name] = zipped.read(matches[0])
    reference = json.loads(values['reference.json'])
    expected = dict(GITHUB_REPOSITORY=repository, GITHUB_SHA=sha,
                    GITHUB_RUN_ID=str(run['id']), GITHUB_RUN_ATTEMPT=str(run['run_attempt']))
    require(reference.get('schemaVersion') == 1 and reference.get('producer') == expected,
            'Changed source reference producer')
    require('reuseSha256' not in reference, 'Chained audit reuse is not allowed')
    require(all(re.fullmatch(r'[a-f0-9]{64}', reference.get(key, ''))
                for key in ('graphSha256', 'planSha256')), 'Missing source graph binding')
    require(reference.get('auditSha256') == digest(values['audit.json'])
            and reference.get('timingsSha256') == digest(values['timings.json']),
            'Changed source evidence bytes')
    audit = json.loads(values['audit.json'])
    require(audit.get('schemaVersion') == 2 and audit.get('plan') == 'maestro-validation'
            and audit.get('targetCount') == 20 and audit.get('failureCount') == 0,
            'Incomplete source audit')
    rows = audit.get('results', [])
    require(len(rows) == 20 and len({row['attribute'] for row in rows}) == 20
            and all(row.get('status') == 'success' and row.get('outputs') for row in rows),
            'Missing successful output obligations')
    return values


def api(path):
    # Only caller-built repository API paths are accepted. Never follow a URL
    # from an artifact payload with the GitHub token.
    return json.loads(subprocess.check_output(['gh', 'api', '--hostname', 'github.com', path], timeout=60))


def download(path):
    # Bound both the archive size and wall clock, including a stalled pipe.
    with tempfile.TemporaryFile() as target:
        process = subprocess.Popen(['gh', 'api', '--hostname', 'github.com', path], stdout=subprocess.PIPE, start_new_session=True)
        deadline = time.monotonic() + 120
        try:
            total = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0 and selector.select(remaining), 'Archive transfer timed out')
                    chunk = os.read(process.stdout.fileno(), 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    require(total <= MAX_ARCHIVE, 'Oversized archive transfer')
                    target.write(chunk)
            require(process.wait(timeout=max(0.1, deadline - time.monotonic())) == 0,
                    'Artifact download failed')
            target.seek(0)
            return target.read()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def restore(env, now):
    repository, sha = env['GITHUB_REPOSITORY'], env['GITHUB_SHA']
    prefix = 'repos/' + repository
    # Use complete API details, not mutable names or a caller-provided run ID.
    runs = api(f'{prefix}/actions/workflows/ci.yml/runs?event=merge_group&head_sha={sha}&status=success&per_page=3')['workflow_runs']
    for candidate in runs:
        try:
            run = api(f"{prefix}/actions/runs/{int(candidate['id'])}")
            verify_run(run, repository, sha, now)
            jobs = api(f"{prefix}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=30")
            require(jobs['total_count'] <= 100 and len(jobs['jobs']) == jobs['total_count'],
                    'Truncated source jobs')
            verify_jobs(jobs['jobs'], run['run_attempt'])
            artifacts = api(f"{prefix}/actions/runs/{run['id']}/artifacts?name=maestro-audit-audit&per_page=30")
            require(artifacts['total_count'] == 1 and len(artifacts['artifacts']) == 1,
                    'Ambiguous source artifact')
            artifact = artifacts['artifacts'][0]
            verify_artifact(artifact, run, repository, sha, now)
            archive = download(f"{prefix}/actions/artifacts/{artifact['id']}/zip")
            values = unpack(archive, artifact, run, repository, sha)
            # Recheck after transfer: a rerun/deletion cannot silently change
            # the provenance while the artifact is being downloaded.
            current = api(f"{prefix}/actions/runs/{run['id']}")
            verify_run(current, repository, sha, now)
            require(current['run_attempt'] == run['run_attempt'], 'Producer reran during transfer')
            current_artifact = api(f"{prefix}/actions/artifacts/{artifact['id']}")
            verify_artifact(current_artifact, current, repository, sha, now)
            require(current_artifact['digest'] == artifact['digest'], 'Artifact changed during transfer')
            destination = Path(env['MAESTRO_CI_AUDIT_MANIFEST']).parent
            require(Path(env['MAESTRO_CI_AUDIT_MANIFEST']).name == 'audit.json'
                    and Path(env['MAESTRO_CI_AUDIT_TIMINGS']) == destination / 'timings.json',
                    'Unexpected audit destinations')
            destination.mkdir(parents=True, exist_ok=True)
            provenance = dict(schemaVersion=1, mode='exact-queue-audit', source=run['html_url'],
                              sourceProducer=json.loads(values['reference.json'])['producer'],
                              artifactId=artifact['id'], artifactDigest=artifact['digest'],
                              sourceReferenceSha256=digest(values['reference.json']),
                              auditSha256=digest(values['audit.json']), timingsSha256=digest(values['timings.json']))
            for name in ('audit.json', 'timings.json'):
                (destination / name).write_bytes(values[name])
            (destination / 'reuse.json').write_text(json.dumps(provenance, sort_keys=True, indent=2) + '\n')
            print('Verified exact-commit queue audit reused; current graph binding and signing remain required.')
            return True
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, zipfile.BadZipFile):
            continue
    return False


def main():
    if not eligible(os.environ):
        return 1
    try:
        # A failed lookup must not leave a stale reuse marker on a fallback.
        destination = Path(os.environ['MAESTRO_CI_AUDIT_MANIFEST']).parent
        (destination / 'reuse.json').unlink(missing_ok=True)
        # GitHub SHA alone is insufficient if something changed the checkout.
        sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
        require(sha == os.environ['GITHUB_SHA'], 'Checkout is not the exact candidate')
        subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], check=True, timeout=10)
        return 0 if restore(os.environ, dt.datetime.now(dt.timezone.utc)) else 1
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        print('Verified queue audit unavailable; running the complete repository audit.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
