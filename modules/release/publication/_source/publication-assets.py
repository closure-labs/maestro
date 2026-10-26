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

sys.path.insert(0, os.environ.get('MAESTRO_DECISIONS_SOURCE', str((Path(__file__).parent / '../../../ci/authority/_source/decisions'))))
import common

_spec = importlib.util.spec_from_file_location('publication_journal', os.environ.get('MAESTRO_PUBLICATION_JOURNAL_SOURCE', str((Path(__file__).parent / 'publication-journal.py'))))
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


def validated_release(release, tag, release_id=None):
    common.require(isinstance(release, dict) and type(release.get('id')) is int
                   and release['id'] > 0 and release.get('tag_name') == tag
                   and (release_id is None or release['id'] == release_id), 'Invalid release identity')
    return release


def release_for(repository, tag, github, release_id=None):
    if release_id is not None:
        return validated_release(github(f'repos/{repository}/releases/{release_id}'), tag, release_id)
    # Authenticated listing includes drafts which by-tag lookup may omit.
    # Exhaust the bounded inventory before treating absence as permission to create.
    matches = []
    for page in range(1, 11):
        values = github(f'repos/{repository}/releases?per_page=100&page={page}')
        common.require(isinstance(values, list) and len(values) <= 100, 'Invalid release listing')
        matches.extend(validated_release(value, tag) for value in values if value.get('tag_name') == tag)
        common.require(len(matches) <= 1, 'Ambiguous release tag inventory')
        if len(values) < 100:
            return matches[0] if matches else None
    raise ValueError('Release discovery exceeds bounded inventory')


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


def upload(repository, tag, paths):
    common.require(os.environ.get('PUBLICATION_REQUIRE_VERIFIED') != 'true',
                   'Verified-only publication forbids asset uploads')
    subprocess.run(['gh', 'release', 'upload', tag, *map(str, paths), '--repo', repository],
                   check=True, capture_output=True, text=True, timeout=1800)


def upload_batches(directory, names):
    """Bound each authorized mutation group; large assets remain singleton writes."""
    batch, size = [], 0
    for name in sorted(names):
        path = directory / name
        length = path.stat().st_size
        if batch and (len(batch) == 8 or size + length > 64 * 1024**2):
            yield batch
            batch, size = [], 0
        batch.append(path)
        size += length
    if batch:
        yield batch


def reconcile(repository, product, directory, tag, revision, publish, authorize,
              github=journal.api, download=remote_digest, send=upload, materialize=None, stage_only=False):
    common.require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?', tag), 'Versioned official release tag required')
    common.require(common.SHA.fullmatch(revision) and product.get('revision') == revision
                   and product.get('repository') == repository, 'Release source differs from approved product')
    assets = product.get('assets')
    common.require(isinstance(assets, dict) and assets and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', name)
                   and common.HASH.fullmatch(digest) for name, digest in assets.items()), 'Immutable release assets required')
    directory = Path(directory)
    for name, digest in assets.items():
        path = directory / name
        common.require((materialize is not None and not path.exists() and not path.is_symlink()) or (path.is_file() and not path.is_symlink() and sha256(path) == digest),
                       'Local release bytes differ from approved asset: ' + name)
    notes = None
    if 'release-notes.md' in assets:
        common.require((directory / 'release-notes.md').stat().st_size <= 65536, 'Release notes exceed bounded size')
        notes = (directory / 'release-notes.md').read_text()
    actual = tag_revision(repository, tag, github)
    common.require(actual is None or actual == revision, 'Existing release tag points at another source')
    common.require(not stage_only or actual is not None, 'Asset batch requires reserved tag')
    common.require(os.environ.get('PUBLICATION_REQUIRE_VERIFIED') != 'true' or actual == revision,
                   'Verified-only publication requires an existing tag')
    if actual is None:
        authorize()
        try:
            github(f'repos/{repository}/git/refs', 'POST', {'ref': 'refs/tags/' + tag, 'sha': revision})
        except journal.GitHubError as error:
            if error.status not in (409, 422):
                raise
        common.require(tag_revision(repository, tag, github) == revision, 'Release tag reservation conflict')
    release = release_for(repository, tag, github)
    common.require(not stage_only or release is not None, 'Asset batch requires reserved draft')
    common.require(os.environ.get('PUBLICATION_REQUIRE_VERIFIED') != 'true'
                   or (release is not None and release.get('draft') is False),
                   'Verified-only publication requires a published release')
    if release is None:
        authorize()
        try:
            release = validated_release(github(f'repos/{repository}/releases', 'POST', {'tag_name': tag, 'target_commitish': revision,
                                                          'name': tag, 'draft': True, 'prerelease': '-' in tag.split('+', 1)[0],
                                                          **({'body': notes} if notes is not None else {})}), tag)
        except journal.GitHubError as error:
            if error.status not in (409, 422):
                raise
        if release is None:
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
    common.require(os.environ.get('PUBLICATION_REQUIRE_VERIFIED') != 'true' or not missing,
                   'Verified-only publication requires all hosted assets')
    if missing and materialize is not None:
        materialize()
    for batch in upload_batches(directory, missing):
        # One live decision per bounded upload command, with no reuse between
        # batches. Large ISO parts are always isolated from other assets.
        common.require(tag_revision(repository, tag, github) == revision, 'Release tag changed while staging')
        authorize()
        for path in batch:
            common.require(sha256(path) == assets[path.name], 'Local asset changed while staging')
        send(repository, tag, batch)
    if stage_only:
        return {'schema': 1, 'status': 'staged', 'tag': tag, 'revision': revision,
                'productHash': common.canonical_hash(product), 'assets': sorted(assets)}
    release = verify_hosted(repository, product, directory, tag, revision, github, download, release['id'])
    authorize()
    return publish_verified(repository, product, directory, tag, revision, release, publish, github)


def release_notes(product, directory):
    if 'release-notes.md' not in product['assets']:
        return None
    path = Path(directory) / 'release-notes.md'
    common.require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536
                   and sha256(path) == product['assets']['release-notes.md'], 'Release notes differ from approved bytes')
    return path.read_text()


def verify_hosted(repository, product, directory, tag, revision, github=journal.api, download=remote_digest, release_id=None):
    """Final complete hosted-byte readback; caller authorizes subsequent writes."""
    common.require(product.get('repository') == repository and product.get('revision') == revision
                   and common.SHA.fullmatch(revision), 'Release source differs from approved product')
    assets = product['assets']
    notes = release_notes(product, directory)
    release = release_for(repository, tag, github, release_id)
    common.require(release is not None and type(release.get('draft')) is bool and release.get('tag_name') == tag
                   and release.get('target_commitish') == revision, 'Release changed while staging')
    common.require(notes is None or release.get('body') == notes, 'Release notes changed while staging')
    remote = inventory(repository, release, github)
    common.require(set(remote) == set(assets), 'Release asset inventory is incomplete or unexpected')
    for name, asset in remote.items():
        common.require(download(repository, asset) == assets[name], 'Hosted bytes differ from approved product: ' + name)
    common.require(tag_revision(repository, tag, github) == revision, 'Release tag changed before publication')
    return release


def publish_verified(repository, product, directory, tag, revision, release, publish, github=journal.api):
    """Write/read back a prepared publication inside the caller's fresh write group."""
    assets = product['assets']
    notes = release_notes(product, directory)
    common.require(os.environ.get('PUBLICATION_REQUIRE_VERIFIED') != 'true' or release.get('draft') is False,
                   'Verified-only publication requires a published release')
    if publish and release.get('draft') is True:
        github(f'repos/{repository}/releases/{release["id"]}', 'PATCH', {'draft': False})
        release = release_for(repository, tag, github, release['id'])
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
    parser.add_argument('--stage-only', action='store_true')
    args = parser.parse_args()
    cfg = common.config(args.config, live=True, enabled=True)
    product = common.load_json(args.product)
    digest = common.canonical_hash(product)
    def authorize():
        result = common.gate(cfg, args.scans, args.product, 'release')
        common.require(result.get('productHash') == digest, 'Approved product changed during publication')
        if os.environ.get('MAESTRO_REQUIRE_UPSTREAM_HANDOFF') == 'true':
            common.command(['maestro-ci-decision-handoff'])
    if not args.stage_only:
        authorize()
    import packet_materialization
    deferred = args.directory.with_suffix('.source.json').exists()
    result = reconcile(cfg['repository'], product, args.directory, args.tag, args.revision, args.publish, authorize,
                       materialize=(lambda: packet_materialization.materialize(args.directory)) if deferred else None, stage_only=args.stage_only)
    if result['status'] == 'published' and os.environ.get('PUBLICATION_RECEIPT'):
        import destinations
        identity = {'tag': args.tag, 'revision': args.revision, 'assets': product['assets']}
        proof = destinations.result('github', identity, identity)
        Path(os.environ['PUBLICATION_RECEIPT']).write_bytes(destinations.canonical(destinations.receipt(proof, product)) + b'\n')
    common.emit(result, args.output)


if __name__ == '__main__':
    sys.exit(common.run(main))
