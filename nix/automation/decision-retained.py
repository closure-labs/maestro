#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recover digest-bound native data after ephemeral Actions artifacts expire."""
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, os.environ.get('MAESTRO_DECISION_CORE', str(Path(__file__).with_name('decisions'))))
import common
import decision_authority as authority
import decision_packets as packets
from security_decisions import canonical_hash


class NoCandidate(Exception):
    """Discovery completed successfully and found no eligible retained work."""


def workflow_metadata(values):
    mapping = {'candidate_run': 'DECISION_CANDIDATE_RUN', 'source_sha': 'DECISION_SOURCE_SHA',
               'evidence_directory': 'DECISION_EVIDENCE_DIRECTORY', 'product': 'DECISION_PRODUCT',
               'scans': 'DECISION_SCANS', 'release': 'DECISION_IS_RELEASE', 'release_tag': 'RELEASE_TAG',
               'release_version': 'RELEASE_VERSION', 'available': 'DECISION_AVAILABLE',
               'proposal_hash': 'DECISION_RETAINED_PROPOSAL', 'retained': 'DECISION_RETAINED'}
    for variable in ('GITHUB_OUTPUT', 'GITHUB_ENV'):
        if os.environ.get(variable):
            with Path(os.environ[variable]).open('a') as stream:
                for key, value in values.items():
                    common.require('\n' not in value and '\r' not in value, 'Unsafe workflow metadata')
                    stream.write((mapping[key] if variable == 'GITHUB_ENV' else key) + '=' + value + '\n')


def pending(cfg):
    proposals = {}
    repository = cfg['repository']
    pulls = authority.collection(authority.github_api, f'repos/{repository}/pulls?state=open&base=main')
    for pull in pulls:
        if (pull.get('user', {}).get('login') != cfg['botLogin'] or pull.get('user', {}).get('type') != 'Bot'
                or pull.get('head', {}).get('repo', {}).get('full_name') != repository
                or not pull.get('head', {}).get('ref', '').startswith('automation/decision-')):
            continue
        files = authority.collection(authority.github_api, f'repos/{repository}/pulls/{pull["number"]}/files')
        common.require(len(files) == pull.get('changed_files') == 1 and files[0].get('status') == 'added',
                       'Pending App proposal changes unexpected files')
        path = files[0].get('filename', '')
        common.require(re.fullmatch(r'automation/decisions/(security|releases)/[0-9a-f]{64}\.json', path),
                       'Pending App proposal has noncanonical decision path')
        proposal = authority.document_at(authority.github_api, repository, path, pull['head']['sha'])
        common.require(authority.proposal_path(proposal) == path, 'Pending decision hash mismatch')
        proposals[canonical_hash(proposal)] = proposal
    return proposals


def select(cfg, records, open_proposals, release_only=False, proposal_hash=None, published_tags=None):
    """Selection schedules verification/rescan work, never grants acceptance."""
    published_tags = published_tags or set()
    candidates = {}
    if not release_only:
        digest, proposal = common.active_security(cfg, records, authenticate=False)
        if proposal and proposal['payload']['disposition'] == 'accepted':
            candidates[digest] = proposal
        for digest, proposal in open_proposals.items():
            if proposal['kind'] == 'security-findings' and proposal['payload'].get('disposition') == 'accepted':
                candidates[digest] = proposal
    else:
        products = {canonical_hash(p['payload']['product']): p['payload']['product'] for p in records.values()
                    if p['kind'] == 'release-product' and isinstance(p['payload'].get('product'), dict)}
        for product in products.values():
            digest, proposal = common.active_release(cfg, records, product, authenticate=False)
            if proposal and proposal['payload']['disposition'] == 'accepted':
                candidates[digest] = proposal
        for digest, proposal in open_proposals.items():
            if proposal['kind'] == 'release-product' and proposal['payload'].get('disposition') == 'accepted':
                candidates[digest] = proposal
        for digest, proposal in list(candidates.items()):
            assets = proposal['payload']['product'].get('assets', {})
            tags = {m[1] for name in assets if (m := re.fullmatch(r'maestro-(v[0-9]+\.[0-9]+\.[0-9]+)\.iso\.sha256', name))}
            common.require(len(tags) == 1, 'Retained official product lacks one exact release tag')
            if next(iter(tags)) in published_tags:
                del candidates[digest]
    if proposal_hash:
        common.require(proposal_hash in candidates, 'Requested retained proposal is not an eligible current candidate')
        return proposal_hash, candidates[proposal_hash]
    # Finish one outstanding human decision before revisiting an older accepted
    # baseline. A pending packet is still authenticated below before any rescan.
    outstanding = {h: p for h, p in candidates.items() if h in open_proposals}
    if outstanding:
        candidates = outstanding
    # Avoid picking an arbitrary historical official release. Explicit selection
    # resolves divergent candidates; published releases have already been removed.
    if not candidates:
        raise NoCandidate('No eligible retained candidate was discovered')
    common.require(len(candidates) == 1, 'Retained recovery needs one unambiguous candidate or --proposal-hash')
    return next(iter(candidates.items()))


def verify_native_files(directory, native):
    """Prove retained inventory/lock bytes, in addition to OCI layer integrity."""
    checksums = directory / 'inputs.sha256'
    evidence = native['evidence']
    common.require(checksums.is_file() and not checksums.is_symlink()
                   and packets.file_hash(checksums) == evidence['inputHashes']['sha256']
                   and checksums.stat().st_size == evidence['inputHashes']['size'], 'Retained input hash evidence mismatch')
    names, found = {'maestro-system.cdx.json', 'xen-orchestra-supply.cdx.json', 'Cargo.lock'}, set()
    for line in checksums.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *](.+)', line)
        common.require(match is not None, 'Malformed retained native input hash')
        name = Path(match[2]).name
        common.require(name in names and name not in found, 'Unexpected retained input identity')
        found.add(name)
        path = directory / 'inventory' / name
        common.require(path.is_file() and not path.is_symlink() and packets.file_hash(path) == match[1],
                       'Retained input bytes differ from authenticated native scan')
    common.require(found == names, 'Incomplete retained native input evidence')
    path = directory / 'inventory/maestro-system.cdx.json'
    common.require(packets.file_hash(path) == evidence['inventory']['sha256']
                   and path.stat().st_size == evidence['inventory']['size'], 'Retained native inventory differs from scan')


def main():
    cli = common.parser(__doc__)
    cli.add_argument('--release-only', action='store_true')
    cli.add_argument('--proposal-hash')
    cli.add_argument('--optional', action='store_true')
    cli.add_argument('--directory', type=Path, default=Path('candidate-evidence'))
    args = cli.parse_args()
    cfg = common.config(args.config, live=True)
    _, records = common.ledger(cfg)
    release_only = args.release_only or os.environ.get('DECISION_RELEASE_ONLY') == 'true'
    releases = authority.collection(authority.github_api, f'repos/{cfg["repository"]}/releases') if release_only else []
    tags = {r['tag_name'] for r in releases if r.get('draft') is False and isinstance(r.get('tag_name'), str)}
    try:
        digest, proposal = select(cfg, records, pending(cfg), release_only, args.proposal_hash, tags)
    except NoCandidate:
        if not args.optional:
            raise
        values = {'available': 'false', 'release': 'false', 'release_tag': '', 'release_version': '',
                  'product': '', 'scans': '', 'evidence_directory': '', 'source_sha': '',
                  'candidate_run': '', 'proposal_hash': '', 'retained': 'false'}
        workflow_metadata(values)
        common.emit(values, args.output)
        return
    packet = proposal['payload'].get('packet', {})
    common.require(isinstance(packet, dict) and 'reference' in packet and 'sha256' in packet, 'Retained evidence packet missing')
    manifest = packets.fetch(packet['reference'], args.directory, packet['sha256'])
    common.require(manifest['producer'] == packet.get('producer'), 'Retained packet producer differs from reviewed proposal')
    scan = common.scans(args.directory / 'scans.json', cfg, allow_expired=True)
    product = common.product(args.directory / 'product.json', cfg, scan)
    common.require(set(scan['profiles']) == {'maestro'}, 'Unexpected retained appliance profile scope')
    verify_native_files(args.directory, scan['profiles']['maestro'])
    producer = dict(scan['producer'], repository=cfg['repository'],
                    revision=scan['producer'].get('revision', scan['revision']), sourceRevision=scan['revision'])
    common.require(manifest['producer'] == producer, 'Retained packet has a different authenticated native producer')
    if proposal['kind'] == 'release-product':
        common.require(proposal['payload']['product'] == product, 'Retained release product differs from proposed exact identity')
    for name, expected in product['assets'].items():
        path = args.directory / name
        common.require(path.is_file() and not path.is_symlink() and packets.file_hash(path) == expected,
                       'Retained immutable release bytes missing or mismatched')
    tags = {m[1] for name in product['assets'] if (m := re.fullmatch(r'maestro-(v[0-9]+\.[0-9]+\.[0-9]+)\.iso\.sha256', name))}
    common.require(not product['assets'] or len(tags) == 1, 'Retained official release tag is ambiguous')
    values = {'candidate_run': str(scan['producer']['runId']), 'source_sha': product['revision'],
              'evidence_directory': str(args.directory), 'product': str(args.directory / 'product.json'),
              'scans': str(args.directory / 'scans.json'), 'release': 'true' if product['assets'] else 'false',
              'release_tag': next(iter(tags), ''), 'release_version': next(iter(tags), '')[1:],
              'available': 'true', 'proposal_hash': digest, 'retained': 'true'}
    workflow_metadata(values)
    common.emit(values, args.output)


if __name__ == '__main__':
    try:
        sys.exit(common.run(main))
    except NoCandidate as error:
        print(json.dumps({'schema': 1, 'status': 'no-candidate', 'error': str(error)}), file=sys.stderr)
        sys.exit(3)
