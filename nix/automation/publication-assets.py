#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage and publish exact approved release bytes without retargeting or clobber."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote

sys.path.insert(0, os.environ.get('MAESTRO_DECISIONS_SOURCE', str(Path(__file__).with_name('decisions'))))
import common

_spec = importlib.util.spec_from_file_location('publication_journal', os.environ.get('MAESTRO_PUBLICATION_JOURNAL_SOURCE', str(Path(__file__).with_name('publication-journal.py'))))
journal = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(journal)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def tag_revision(repository, tag, github):
    try:
        result = github(f'repos/{repository}/git/ref/tags/{quote(tag, safe="")}')
    except journal.GitHubError as error:
        if error.status == 404:
            return None
        raise
    common.require(result.get('ref') == 'refs/tags/' + tag, 'Unexpected release tag identity')
    obj = result.get('object', {})
    for _ in range(5):
        common.require(common.SHA.fullmatch(obj.get('sha', '')), 'Invalid release tag object')
        if obj.get('type') == 'commit':
            return obj['sha']
        common.require(obj.get('type') == 'tag', 'Release tag does not resolve to a commit')
        obj = github(f'repos/{repository}/git/tags/{obj["sha"]}').get('object', {})
    raise ValueError('Release tag nesting exceeds supported bound')


def release_for(repository, tag, github):
    try:
        release = github(f'repos/{repository}/releases/tags/{quote(tag, safe="")}')
    except journal.GitHubError as error:
        if error.status == 404:
            return None
        raise
    common.require(type(release.get('id')) is int and release['id'] > 0, 'Invalid release ID')
    return release


def inventory(repository, release, github):
    values = common.authority.collection(github, f'repos/{repository}/releases/{release["id"]}/assets')
    result = {}
    for asset in values:
        name = asset.get('name')
        common.require(isinstance(name, str) and name not in result and type(asset.get('id')) is int
                       and asset['id'] > 0 and asset.get('state') == 'uploaded', 'Invalid or duplicate remote release asset')
        result[name] = asset
    return result


def remote_digest(repository, asset):
    with tempfile.TemporaryFile() as handle:
        result = subprocess.run(['gh', 'api', '-H', 'Accept: application/octet-stream',
                                 f'repos/{repository}/releases/assets/{asset["id"]}'],
                                stdout=handle, stderr=subprocess.PIPE, timeout=1800)
        common.require(result.returncode == 0, 'Unable to verify remote release bytes')
        handle.seek(0)
        digest = hashlib.sha256()
        size = 0
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
            size += len(block)
        common.require(size == asset.get('size'), 'Remote release size differs from asset metadata')
        return digest.hexdigest()


def upload(repository, tag, path):
    subprocess.run(['gh', 'release', 'upload', tag, str(path), '--repo', repository],
                   check=True, capture_output=True, text=True, timeout=1800)


def reconcile(repository, product, directory, tag, revision, publish, authorize,
              github=journal.api, download=remote_digest, send=upload):
    common.require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?', tag), 'Versioned official release tag required')
    common.require(common.SHA.fullmatch(revision) and product.get('revision') == revision
                   and product.get('repository') == repository, 'Release source differs from approved product')
    assets = product.get('assets')
    common.require(isinstance(assets, dict) and assets and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', name)
                   and common.HASH.fullmatch(digest) for name, digest in assets.items()), 'Immutable release assets required')
    directory = Path(directory)
    for name, digest in assets.items():
        path = directory / name
        common.require(path.is_file() and not path.is_symlink() and sha256(path) == digest,
                       'Local release bytes differ from approved asset: ' + name)
    notes = None
    if 'release-notes.md' in assets:
        common.require((directory / 'release-notes.md').stat().st_size <= 65536, 'Release notes exceed bounded size')
        notes = (directory / 'release-notes.md').read_text()
    actual = tag_revision(repository, tag, github)
    common.require(actual is None or actual == revision, 'Existing release tag points at another source')
    if actual is None:
        authorize()
        try:
            github(f'repos/{repository}/git/refs', 'POST', {'ref': 'refs/tags/' + tag, 'sha': revision})
        except journal.GitHubError as error:
            if error.status not in (409, 422):
                raise
        common.require(tag_revision(repository, tag, github) == revision, 'Release tag reservation conflict')
    release = release_for(repository, tag, github)
    if release is None:
        authorize()
        try:
            github(f'repos/{repository}/releases', 'POST', {'tag_name': tag, 'target_commitish': revision,
                                                          'name': tag, 'draft': True, 'prerelease': '-' in tag.split('+', 1)[0],
                                                          **({'body': notes} if notes is not None else {})})
        except journal.GitHubError as error:
            if error.status not in (409, 422):
                raise
        release = release_for(repository, tag, github)
        common.require(release is not None, 'Created release cannot be reconciled')
    common.require(release.get('tag_name') == tag and release.get('target_commitish') == revision and type(release.get('draft')) is bool,
                   'Existing release target differs from exact approved source')
    common.require(notes is None or release.get('body') == notes, 'Existing release notes differ from approved bytes')
    remote = inventory(repository, release, github)
    common.require(set(remote) <= set(assets), 'Existing release contains unapproved asset names')
    for name, asset in remote.items():
        common.require(download(repository, asset) == assets[name], 'Existing release asset bytes differ: ' + name)
    missing = set(assets) - set(remote)
    common.require(release.get('draft') is True or not missing, 'Published release is incomplete; refusing mutation')
    for name in sorted(missing):
        # Check source and authorization again before every remote mutation.
        common.require(tag_revision(repository, tag, github) == revision, 'Release tag changed while staging')
        authorize()
        common.require(sha256(directory / name) == assets[name], 'Local asset changed while staging')
        send(repository, tag, directory / name)
    # Reread everything after partial recovery or upload; metadata alone never
    # substitutes for hashing the actual hosted asset bytes.
    release = release_for(repository, tag, github)
    common.require(release is not None and type(release.get('draft')) is bool and release.get('tag_name') == tag
                   and release.get('target_commitish') == revision, 'Release changed while staging')
    common.require(notes is None or release.get('body') == notes, 'Release notes changed while staging')
    remote = inventory(repository, release, github)
    common.require(set(remote) == set(assets), 'Release asset inventory is incomplete or unexpected')
    for name, asset in remote.items():
        common.require(download(repository, asset) == assets[name], 'Hosted bytes differ from approved product: ' + name)
    common.require(tag_revision(repository, tag, github) == revision, 'Release tag changed before publication')
    authorize()
    if publish and release.get('draft') is True:
        github(f'repos/{repository}/releases/{release["id"]}', 'PATCH', {'draft': False})
        release = release_for(repository, tag, github)
        common.require(release is not None and release.get('draft') is False
                       and release.get('tag_name') == tag and release.get('target_commitish') == revision,
                       'Release publication did not reach the expected state')
        common.require(notes is None or release.get('body') == notes, 'Published release notes differ from approved bytes')
    return {'schema': 1, 'status': 'published' if release.get('draft') is False else 'staged',
            'tag': tag, 'revision': revision, 'productHash': common.canonical_hash(product), 'assets': sorted(assets)}


def main():
    parser = common.parser(__doc__)
    parser.add_argument('--product', required=True, type=Path)
    parser.add_argument('--scans', required=True, type=Path)
    parser.add_argument('--directory', default='release', type=Path)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    cfg = common.config(args.config, live=True, enabled=True)
    product = common.load_json(args.product)
    digest = common.canonical_hash(product)
    def authorize():
        result = common.gate(cfg, args.scans, args.product, 'release')
        common.require(result.get('productHash') == digest, 'Approved product changed during publication')
        if os.environ.get('MAESTRO_REQUIRE_UPSTREAM_HANDOFF') == 'true':
            common.command(['maestro-ci-decision-handoff'])
    authorize()
    common.emit(reconcile(cfg['repository'], product, args.directory, args.tag, args.revision, args.publish, authorize), args.output)


if __name__ == '__main__':
    sys.exit(common.run(main))
