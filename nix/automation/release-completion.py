#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compose reservation or GitHub completion within one fresh release write group."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys

_spec = importlib.util.spec_from_file_location('release_assets', os.environ.get(
    'MAESTRO_PUBLICATION_ASSETS_SOURCE', str(Path(__file__).with_name('publication-assets.py'))))
assets = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(assets)
common, journal = assets.common, assets.journal


def identity(repository, product, tag, revision):
    common.require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?', tag),
                   'Versioned official release tag required')
    common.require(common.SHA.fullmatch(revision) and product.get('revision') == revision
                   and product.get('repository') == repository, 'Release source differs from approved product')
    values = product.get('assets')
    common.require(isinstance(values, dict) and values and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', name)
                   and common.HASH.fullmatch(digest) for name, digest in values.items()), 'Immutable release assets required')


def readback(repository, tag, github):
    """Observe uncertain outcomes; never retry or turn readback into authority."""
    assets.tag_revision(repository, tag, github)
    assets.release_for(repository, tag, github)
    try:
        github(f'repos/{repository}/git/ref/heads/' + journal.BRANCH)
    except journal.GitHubError as error:
        if error.status != 404:
            raise
    try:
        github(f'repos/{repository}/contents/publications/{tag}.json?ref=' + journal.BRANCH)
    except journal.GitHubError as error:
        if error.status != 404:
            raise


def reserve(repository, product, directory, tag, revision, authorize, github=journal.api):
    identity(repository, product, tag, revision)
    notes = assets.release_notes(product, directory)
    actual = assets.tag_revision(repository, tag, github)
    common.require(actual is None or actual == revision, 'Existing release tag points at another source')
    release = assets.release_for(repository, tag, github)
    if release is not None:
        common.require(release.get('target_commitish') == revision and type(release.get('draft')) is bool
                       and (notes is None or release.get('body') == notes), 'Existing draft differs from approved product')
    plan = journal.prepare_transition(repository, common.canonical_hash(product), tag, 'github', 'pending', github)
    authorize()
    common.require(assets.tag_revision(repository, tag, github) == actual, 'Release tag changed during reservation authority')
    current = assets.release_for(repository, tag, github)
    common.require(current == release, 'Release draft changed during reservation authority')
    try:
        journal.write_prepared(plan, github)
        if actual is None:
            github(f'repos/{repository}/git/refs', 'POST', {'ref': 'refs/tags/' + tag, 'sha': revision})
            common.require(assets.tag_revision(repository, tag, github) == revision, 'Release tag reservation conflict')
        if release is None:
            github(f'repos/{repository}/releases', 'POST', {'tag_name': tag, 'target_commitish': revision,
                   'name': tag, 'draft': True, 'prerelease': '-' in tag.split('+', 1)[0],
                   **({'body': notes} if notes is not None else {})})
            release = assets.release_for(repository, tag, github)
            common.require(release is not None and release.get('draft') is True
                           and release.get('target_commitish') == revision
                           and (notes is None or release.get('body') == notes), 'Draft reservation readback differs')
    except (ValueError, subprocess.SubprocessError, OSError):
        readback(repository, tag, github)
        raise
    return plan['document']


def complete(repository, product, directory, tag, revision, authorize,
             github=journal.api, download=assets.remote_digest):
    identity(repository, product, tag, revision)
    release = assets.verify_hosted(repository, product, directory, tag, revision, github, download)
    observed = {'tag': tag, 'revision': revision, 'assets': product['assets']}
    proof = journal.destinations.result('github', observed, observed)
    receipt = journal.destinations.receipt(proof, product)
    plan = journal.prepare_transition(repository, common.canonical_hash(product), tag, 'github', 'complete', github, receipt)
    authorize()
    common.require(assets.tag_revision(repository, tag, github) == revision, 'Release tag changed during completion authority')
    current = assets.release_for(repository, tag, github, release['id'])
    common.require(all(current.get(key) == release.get(key) for key in ('id', 'tag_name', 'target_commitish', 'draft', 'body')),
                   'Release changed during completion authority')
    try:
        result = assets.publish_verified(repository, product, directory, tag, revision, release, True, github)
        journal.write_prepared(plan, github)
    except (ValueError, subprocess.SubprocessError, OSError):
        readback(repository, tag, github)
        raise
    return result, receipt


def main():
    parser = common.parser(__doc__)
    parser.add_argument('--product', required=True, type=Path)
    parser.add_argument('--scans', required=True, type=Path)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--reserve', action='store_true')
    args = parser.parse_args()
    cfg = common.config(args.config, live=True, enabled=True)
    product = common.load_json(args.product)
    digest = common.canonical_hash(product)
    def authorize():
        result = common.gate(cfg, args.scans, args.product, 'release')
        common.require(result.get('productHash') == digest, 'Approved product changed during publication')
        common.command(['maestro-ci-decision-handoff'])
    if args.reserve:
        result = reserve(cfg['repository'], product, args.directory, args.tag, args.revision, authorize)
    else:
        result, receipt = complete(cfg['repository'], product, args.directory, args.tag, args.revision, authorize)
        if os.environ.get('PUBLICATION_RECEIPT'):
            Path(os.environ['PUBLICATION_RECEIPT']).write_bytes(journal.destinations.canonical(receipt) + b'\n')
    common.emit(result, args.output)


if __name__ == '__main__':
    sys.exit(common.run(main))
