#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only official release integrity; never current health or risk admission."""
import gzip
import hashlib
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import importlib.util


def module(name, variable, fallback):
    spec = importlib.util.spec_from_file_location(name, os.environ.get(variable, Path(__file__).parent / fallback))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


publication = module('public_probe_publication', 'MAESTRO_NATIVE_PUBLICATION_SOURCE', 'native-publication.py')
native = publication.native
require = native.require
locator = module('public_probe_locator', 'MAESTRO_NATIVE_RELEASE_TARGET_SOURCE', 'native-release-target.py')
refresh = module('public_probe_refresh', 'MAESTRO_NATIVE_REFRESH_SOURCE', 'native-refresh.py')
BUDGET_SECONDS = 3000
MAX_ISO = 32 * 1024**3
MAX_DOCUMENT = 64 * 1024**2


def select(policy, api=native.api):
    require(os.environ.get('GITHUB_REPOSITORY') == native.REPO
        and os.environ.get('GITHUB_REF') == 'refs/heads/main'
        and os.environ.get('GITHUB_EVENT_NAME') in ('schedule', 'workflow_dispatch')
        and isinstance(policy, str) and re.fullmatch(r'[0-9a-f]{40}', policy),
        'Protected official public probe required')
    latest = api('releases/latest')
    require(type(latest.get('id')) is int and latest['id'] > 0 and latest.get('draft') is False
        and latest.get('prerelease') is False, 'Stable official release required')
    target = locator.fetch(latest.get('tag_name'), None, policy, discover_signer=True)
    require(target['releaseId'] == latest['id'], 'Official release changed during selection')
    return target


def current(target, policy, api=native.api):
    refresh.official_current(target, api=api)
    require(locator.fetch(target['tag'], target['publicationRevision'], policy) == target,
            'Official signed release changed during consumer verification')


def download(row, path, execute=native.operations.run):
    size = row['size']
    def cap():
        resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
    with path.open('xb') as out, tempfile.TemporaryFile() as err:
        execute(['gh', 'api', '--method', 'GET', '-H', 'Accept: application/octet-stream',
            f'repos/{native.REPO}/releases/assets/{row["id"]}'], stdout=out, stderr=err,
            check=True, timeout=600, preexec_fn=cap)
        require(out.tell() == size and err.tell() <= MAX_DOCUMENT, 'Public asset transfer differs from bound')
    require('sha256:' + native.file_hash(path) == row['digest'], 'Public asset bytes differ from signed inventory')


def assets(bundle, target, root, api=native.api, transfer=download, verify=native.response):
    records = target['assets']
    base = 'maestro-' + target['tag']
    filename = base + '.iso'
    parts = sorted(name for name in records if name.startswith(filename + '.part-'))
    extras = {filename + '.sha256'} | {base + '.' + kind + '.json.gz' + suffix
        for kind in ('spdx', 'cdx') for suffix in ('', '.sha256')}
    require(0 < len(parts) <= 18 and parts == [filename + '.part-' + f'{i:02d}' for i in range(1, len(parts) + 1)]
        and set(records) == set(parts) | extras, 'Exact supported public asset layout required')
    total = sum(records[name]['size'] for name in parts)
    require(0 < total <= MAX_ISO and all(0 < records[n]['size'] <= MAX_DOCUMENT for n in extras)
        and all(records[n]['size'] > 0 for n in parts), 'Public release exceeds consumer bounds')
    require(shutil.disk_usage(root).free >= total + max(records[n]['size'] for n in parts) + 256 * 1024**2,
        'Insufficient disposable consumer disk headroom')
    release = api('releases/tags/' + target['tag'])
    rows = release.get('assets', [])
    require(release.get('id') == target['releaseId'] and len(rows) == len(records) + 1
        and len({r.get('name') for r in rows}) == len(rows), 'Public inventory changed before download')
    remote = {r['name']: r for r in rows}
    require(set(remote) == set(records) | {'native-release-staging.json'}, 'Unexpected public receipt asset')
    for name, record in records.items():
        row = remote.get(name, {})
        require(type(row.get('id')) is int and row['id'] > 0 and row.get('state') == 'uploaded'
            and type(row.get('size')) is int and row['size'] == record['size']
            and row.get('digest') == 'sha256:' + record['sha256'], 'Public asset descriptor changed')
    iso = root / filename
    with iso.open('xb') as output:
        for name in parts:
            path = root / name
            transfer(remote[name], path)
            with path.open('rb') as source:
                shutil.copyfileobj(source, output, 1024**2)
            path.unlink()
    require(iso.stat().st_size == total and native.file_hash(iso) == target['isoSha256'],
        'Public ISO differs from authenticated boot/inventory')
    for name in sorted(extras):
        transfer(remote[name], root / name)
    require((root / (filename + '.sha256')).read_bytes() == (target['isoSha256'] + '  ' + filename + '\n').encode(),
        'Public ISO checksum differs')
    for kind in ('spdx', 'cdx'):
        name = base + '.' + kind + '.json.gz'
        path = root / name
        require((root / (name + '.sha256')).read_bytes() == (records[name]['sha256'] + '  ' + name + '\n').encode(),
            'Public SBOM checksum differs')
        original = bundle['directory'] / ('maestro-system.' + kind + '.json')
        remaining = original.stat().st_size
        digest = hashlib.sha256()
        with gzip.open(path, 'rb') as stream:
            while remaining:
                block = stream.read(min(1024**2, remaining))
                require(block, 'Public SBOM truncated')
                remaining -= len(block)
                digest.update(block)
            require(not stream.read(1), 'Public SBOM exceeds authenticated inventory')
        require(digest.hexdigest() == native.file_hash(original), 'Public SBOM differs from authenticated inventory')
    spdx = native.load_json(bundle['directory'] / 'maestro-system.spdx.json')
    for predicate in ('https://slsa.dev/provenance/v1', 'https://spdx.dev/Document/v2.3'):
        proof = verify('attestation', 'verify', str(iso), '--repo', native.REPO,
            '--signer-workflow', native.REPO + '/.github/workflows/release.yml', '--source-ref', 'refs/heads/main',
            '--source-digest', target['publicationRevision'], '--signer-digest', target['publicationRevision'],
            '--deny-self-hosted-runners', '--predicate-type', predicate, '--format', 'json')
        def matches(row):
            statement = row.get('verificationResult', {}).get('statement', {})
            return statement.get('predicateType') == predicate and any(
                s.get('name') == filename and s.get('digest', {}).get('sha256') == target['isoSha256']
                for s in statement.get('subject', [])) and (predicate != 'https://spdx.dev/Document/v2.3' or statement.get('predicate') == spdx)
        require(isinstance(proof, list) and any(matches(row) for row in proof), 'Exact final-name ISO provenance/SPDX required')
    iso.unlink()
    return dict(isoBytesVerified=True, releaseAssetsVerified=True, finalNameAttestationsVerified=True)


def run():
    policy = os.environ.get('GITHUB_SHA')
    target = select(policy)
    loader = module('public_probe_stage', 'MAESTRO_NATIVE_STAGE_SOURCE', 'native-stage.py')
    reader = module('public_probe_reader', 'MAESTRO_NATIVE_CONSUMER_SOURCE', '../../../release/consumer/_source/consumer-probe.py')
    with tempfile.TemporaryDirectory(prefix='maestro-public-probe-', dir=os.environ.get('RUNNER_TEMP')) as temp:
        root = Path(temp)
        directory = root / 'original'
        payload = root / 'public'
        payload.mkdir()
        origin = loader.stage_refresh(directory, target['runId'], target['runAttempt'], target['revision'], None, discover_origin=True)
        with native.verified_inventory(directory, target['runId'], target['runAttempt'], target['revision'],
                Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY']), origin, policy_revision=policy) as bundle:
            refresh.official_binding(bundle, target)
            result = assets(bundle, target, payload)
            result.update(reader.probe(bundle['product'], publication.CACHE, publication.KEY))
            current(target, policy)
    result.update(status='verified-public-release-integrity', authorization=False, publicationReady=False,
        findingsAccepted=False, currentHealthVerified=False, inventoryVerified=True, narBytesVerified=True,
        tag=target['tag'], sourceRevision=target['revision'], sourceRun=target['runId'], sourceAttempt=target['runAttempt'])
    publication.emit(result)


def main():
    with native.operations.budget(BUDGET_SECONDS):
        run()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, EOFError, subprocess.SubprocessError, MemoryError, RecursionError) as error:
        publication.emit(dict(status='blocked', authorization=False, publicationReady=False,
            findingsAccepted=False, currentHealthVerified=False, error=type(error).__name__), error=True)
        sys.exit(2)
