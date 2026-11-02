#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage unique artifact identities from exact CI runs; scheduling is not admission."""
import hashlib
import datetime as dt
import json
import re
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile

REPO = 'closure-labs/maestro'
CAP = 256 * 1024**2


def api(path):
    import resource
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        def cap():resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**2, 4 * 1024**2))
        subprocess.run(['gh', 'api', '--method', 'GET', 'repos/' + REPO + '/' + path],
                       stdout=out, stderr=err, check=True, timeout=30, preexec_fn=cap)
        out.seek(0)
        return json.load(out)


def select(run, revision, name):
    rows = []
    for page in range(1, 11):
        response = api(f'actions/runs/{run}/artifacts?per_page=100&page={page}')
        values = response['artifacts']
        rows.extend(v for v in values if v['name'] == name)
        if len(values) < 100:
            break
    else:
        raise ValueError('Artifact inventory exceeds bound')
    if len(rows) != 1:
        raise ValueError('Missing or ambiguous exact artifact: ' + name)
    row = rows[0]
    if (row['expired'] or row['workflow_run']['id'] != run or (revision is not None and row['workflow_run']['head_sha'] != revision)
            or row['workflow_run']['head_branch'] != 'main' or not re.fullmatch('sha256:[0-9a-f]{64}', row.get('digest', ''))
            or dt.datetime.fromisoformat(row['expires_at'].replace('Z','+00:00')) <= dt.datetime.now(dt.timezone.utc)):
        raise ValueError('Changed or expired exact artifact')
    return row


def download(row, target, names, budget, limit):
    import resource
    import zipfile
    if type(row['size_in_bytes']) is not int or not 0 < row['size_in_bytes'] <= limit or budget[0] + row['size_in_bytes'] > limit:
        raise ValueError('Artifact exceeds staging resource bound')
    if type(row.get('id')) is not int or row['archive_download_url'] != f"https://api.github.com/repos/{REPO}/actions/artifacts/{row['id']}/zip":
        raise ValueError('Unexpected artifact download endpoint')
    with tempfile.TemporaryFile() as stream:
        def cap():resource.setrlimit(resource.RLIMIT_FSIZE, (row['size_in_bytes'], row['size_in_bytes']))
        subprocess.run(['gh', 'api', '--method', 'GET', row['archive_download_url']], stdout=stream,
                       check=True, timeout=300, preexec_fn=cap)
        if stream.tell() != row['size_in_bytes']:
            raise ValueError('Artifact ZIP size changed')
        budget[0] += stream.tell(); stream.seek(0)
        if 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() != row['digest']:
            raise ValueError('Artifact ZIP digest changed')
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            seen = set(); selected = set()
            if len(archive.infolist()) > 128:
                raise ValueError('Too many archive members')
            for entry in archive.infolist():
                path = PurePosixPath(entry.filename)
                if (path.is_absolute() or '..' in path.parts or '\\' in entry.filename or entry.filename in seen
                        or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR) or entry.flag_bits & 1):
                    raise ValueError('Unsafe artifact ZIP member')
                seen.add(entry.filename)
                if entry.is_dir() or (names is not None and entry.filename not in names):
                    continue
                cap_bytes = 64 * 1024**2 if names is not None else limit
                if not 0 < entry.file_size <= cap_bytes or budget[0] + entry.file_size > limit:
                    raise ValueError('Expanded artifact exceeds staging resource bound')
                destination = target / (names[entry.filename] if names is not None else entry.filename)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, destination.open('xb') as output:
                    remaining = entry.file_size
                    while remaining:
                        block = source.read(min(1024**2, remaining))
                        if not block:
                            raise ValueError('Truncated artifact')
                        output.write(block); remaining -= len(block)
                    if source.read(1):
                        raise ValueError('Artifact member grew')
                budget[0] += entry.file_size; selected.add(entry.filename)
            if names is not None and selected != set(names):
                raise ValueError('Missing allowlisted artifact files')


def stage(directory, run, attempt, revision, origin):
    if directory.exists() or type(run) is not int or run <= 0 or type(attempt) is not int or attempt <= 0 or not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('New staging directory and exact producer required')
    directory.mkdir(parents=True); budget = [0]
    try:
        download(select(run, revision, 'maestro-ci-result'), directory, {'ci-result.json':'ci-result.json'}, budget, CAP)
        result = json.loads((directory / 'ci-result.json').read_text())
        if result['producer']['GITHUB_RUN_ATTEMPT'] != str(attempt):
            raise ValueError('Changed current producer attempt')
        download(select(run, revision, 'maestro-inventory-binding'), directory, {'manifest.json':'inventory-binding.json'}, budget, CAP)
        report_names = ('product.json','scans.json','security-result.json','findings.json',
                        'source-policy.json','effective-policy.json','critical-applicability.json')
        download(select(run, revision, 'maestro-security-report'), directory, {n:n for n in report_names}, budget, CAP)
        if result['boot']['disposition'] == 'verified-retained':
            if origin is None:raise ValueError('Explicit original boot producer required')
            run_id, old_attempt, old_revision = origin
            download(select(run_id, old_revision, 'maestro-ci-result'), directory, {'ci-result.json':'original-ci-result.json'}, budget, CAP)
            old = json.loads((directory / 'original-ci-result.json').read_text())
            if old['producer']['GITHUB_RUN_ATTEMPT'] != str(old_attempt):
                raise ValueError('Changed original producer attempt')
            download(select(run_id, old_revision, 'maestro-installer-boot-log'), directory, {'qemu-boot.log':'original-boot.log'}, budget, CAP)
        elif result['boot']['disposition'] != 'executed' or origin is not None:
            raise ValueError('Unsupported or relabelled boot producer')
        download(select(run, revision, 'maestro-qualification-state'), directory,
                 {'maestro-qualification-state.json':'stage-state.json'}, budget, CAP)
        state = json.loads((directory / 'stage-state.json').read_text())
        if state['source_commit'] != revision or type(state['evidence_run_id']) is not int or state['evidence_run_id'] <= 0:
            raise ValueError('Changed evidence source pointer')
        documents = json.loads((directory / 'inventory-binding.json').read_text())['evidenceFiles']
        # Only scheduling uses the pointer; the current signed result binds every
        # selected document hash. There is no latest/historical decision choice.
        download(select(state['evidence_run_id'], None, 'maestro-evidence'), directory,
                 {n:n for n in documents}, budget, CAP)
    except BaseException:
        shutil.rmtree(directory)
        raise


def transport(run, revision, directory):
    if directory.exists():raise ValueError('New transport directory required')
    directory.mkdir()
    try:
        # Existing retained transport contract remains until its last consumer
        # migrates. Nothing is downloaded here until the mandatory verdict passes.
        row = select(run, revision, 'maestro-distribution-transport')
        download(row, directory, None, [0], 16 * 1024**3)
        return directory
    except BaseException:
        shutil.rmtree(directory);raise
