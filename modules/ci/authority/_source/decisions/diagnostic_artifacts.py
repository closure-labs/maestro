# SPDX-License-Identifier: Apache-2.0
"""Job-local diagnostic objects and a strict v1/v2 artifact reader."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

DIGEST = re.compile(r'[0-9a-f]{64}')
MEMBER = re.compile(r'(?:[0-9a-f]{32}\.(?:result|summary|profile|freshness|stage)\.json|(?:cache|flakehub|github)-receipt\.json|objects/[0-9a-f]{64}\.result\.json)')


def regular_directory(path, create=False):
    path = Path(path).absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in ('.', '..'):
            raise ValueError('Unsafe diagnostic directory')
        current /= part
        if create:
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
        if current.is_symlink() or not current.is_dir():
            raise ValueError('Unsafe diagnostic directory')
    return path


def open_member(root, name):
    if not isinstance(name, str) or not MEMBER.fullmatch(name):
        raise ValueError('Unsafe diagnostic member')
    descriptor = os.open(regular_directory(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        member = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            if not stat.S_ISREG(os.fstat(member).st_mode):
                raise ValueError('Nonregular diagnostic member')
            return os.fdopen(member, 'rb')
        except BaseException:
            os.close(member)
            raise
    finally:
        os.close(descriptor)


def fingerprint(root, name):
    with open_member(root, name) as stream:
        size = os.fstat(stream.fileno()).st_size
        return {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(), 'bytes': size}


def read_json(root, name, limit=64 * 1024):
    with open_member(root, name) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Oversized diagnostic metadata')
    return json.loads(raw)


def atomic_write(root, name, raw, immutable=False):
    if not MEMBER.fullmatch(name):
        raise ValueError('Unsafe diagnostic member')
    root = regular_directory(root)
    parent = regular_directory((root / name).parent, create=True)
    expected = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    with tempfile.NamedTemporaryFile(dir=parent, prefix='.pending-', delete=False) as stream:
        pending = Path(stream.name)
        try:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            if immutable:
                try:
                    os.link(pending, root / name)
                except FileExistsError:
                    if fingerprint(root, name) != expected:
                        raise ValueError('Diagnostic object digest conflict')
            else:
                if (root / name).is_symlink():
                    raise ValueError('Unsafe diagnostic member')
                os.replace(pending, root / name)
        finally:
            pending.unlink(missing_ok=True)
    return name


def store(root, raw):
    digest = hashlib.sha256(raw).hexdigest()
    name = 'objects/' + digest + '.result.json'
    atomic_write(root, name, raw, immutable=True)
    return name


def verify(root):
    """Verify retained bytes without rerunning gates or interpreting authority."""
    root = regular_directory(root)
    path = root / 'manifest.json'
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Nonregular diagnostic manifest')
        raw = stream.read(16 * 1024**2 + 1)
    if len(raw) > 16 * 1024**2:
        raise ValueError('Oversized diagnostic manifest')
    manifest = json.loads(raw)
    if type(manifest.get('schema')) is not int or manifest['schema'] not in (1, 2) or not isinstance(manifest.get('files'), dict):
        raise ValueError('Unsupported diagnostic manifest')
    for name, record in manifest['files'].items():
        if fingerprint(root, name) != record:
            raise ValueError('Diagnostic file integrity failure')
        if name.startswith('objects/') and record['sha256'] != Path(name).name[:64]:
            raise ValueError('Diagnostic object identity mismatch')
        if name.endswith('.profile.json'):
            import diagnostic_requests
            profile = read_json(root, name, 1024 * 1024)
            if name != profile['execution'] + '.profile.json':
                raise ValueError('Mismatched execution profile')
            diagnostic_requests.validate(profile)
    actual = set()
    for member in root.rglob('*'):
        if member.is_symlink() or not (member.is_file() or member.is_dir()):
            raise ValueError('Unsafe diagnostic member')
        if member.is_dir():
            if member.relative_to(root).as_posix() != 'objects':
                raise ValueError('Unexpected diagnostic directory')
        elif member != root / 'manifest.json':
            actual.add(member.relative_to(root).as_posix())
    if actual != set(manifest['files']):
        raise ValueError('Diagnostic inventory differs')
    occurrences = []
    for name in sorted(manifest['files']):
        if not name.endswith('.summary.json'):
            continue
        summary = read_json(root, name, limit=4096)
        digest = summary.get('evidenceDigest')
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError('Invalid diagnostic evidence digest')
        reference = (name.replace('.summary.json', '.result.json') if manifest['schema'] == 1
                     else 'objects/' + digest + '.result.json')
        if reference not in manifest['files'] or manifest['files'][reference]['sha256'] != digest:
            raise ValueError('Missing or conflicting diagnostic object')
        if manifest['schema'] == 2 and summary.get('resultReference') != reference:
            raise ValueError('Diagnostic result reference differs')
        occurrences.append({'summary': name, 'execution': summary['execution'], 'kind': summary['kind'],
                            'elapsedSeconds': summary['elapsedSeconds'], 'resultReference': reference})
    if manifest['schema'] == 2 and manifest.get('occurrences') != occurrences:
        raise ValueError('Diagnostic occurrences differ')
    return manifest
