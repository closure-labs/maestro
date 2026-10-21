#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recover digest-bound native data after ephemeral Actions artifacts expire."""
import json
import datetime as dt
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, os.environ.get('MAESTRO_DECISION_CORE', str(Path(__file__).with_name('decisions'))))
import common
import scheduling
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
        # The list endpoint omits changed_files. Bind the detail response to
        # the discovered head before checking its complete changed-file count.
        detail = authority.github_api(f'repos/{repository}/pulls/{pull["number"]}')
        common.require(detail.get('number') == pull['number'] and detail.get('state') == 'open'
                       and detail.get('user', {}).get('login') == cfg['botLogin']
                       and detail.get('user', {}).get('type') == 'Bot'
                       and detail.get('head', {}).get('sha') == pull['head']['sha']
                       and detail.get('head', {}).get('ref') == pull['head']['ref']
                       and detail.get('head', {}).get('repo', {}).get('full_name') == repository
                       and detail.get('base', {}).get('ref') == 'main',
                       'Pending App proposal changed during discovery')
        files = authority.collection(authority.github_api, f'repos/{repository}/pulls/{pull["number"]}/files')
        common.require(type(detail.get('changed_files')) is int
                       and len(files) == detail['changed_files'] == 1 and files[0].get('status') == 'added',
                       'Pending App proposal changes unexpected files')
        path = files[0].get('filename', '')
        common.require(re.fullmatch(r'automation/decisions/(security|releases)/[0-9a-f]{64}\.json', path),
                       'Pending App proposal has noncanonical decision path')
        proposal = authority.document_at(authority.github_api, repository, path, pull['head']['sha'])
        common.require(authority.proposal_path(proposal) == path, 'Pending decision hash mismatch')
        proposals[canonical_hash(proposal)] = proposal
    return proposals


def select(cfg, records, open_proposals, release_only=False, proposal_hash=None, published_tags=None, suppressed_products=None):
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
            if (next(iter(tags)) in published_tags
                    or canonical_hash(proposal['payload']['product']) in (suppressed_products or set())):
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


def current_published_products(cfg, records, published, requested=None):
    """Suppress exact active products; refresh only the newest intended official release by default."""
    if requested:
        return set()  # Explicit historical recovery preserves its exact selection.
    candidates = {}
    for proposal in records.values():
        if proposal['kind'] != 'release-product':
            continue
        identity = proposal['payload']['product']
        _, active = common.active_release(cfg, records, identity, authenticate=False)
        if active is not None and active['payload']['disposition'] == 'accepted':
            versions = {m[1] for name in identity.get('assets', {})
                        if (m := re.fullmatch(r'maestro-(v[0-9]+\.[0-9]+\.[0-9]+)\.iso\.sha256', name))}
            common.require(len(versions) == 1, 'Retained product requires one official version')
            candidates[canonical_hash(identity)] = (active, next(iter(versions)))
    if not candidates:
        return set()
    version = lambda tag: tuple(map(int, tag.removeprefix('v').split('.')))
    newest = max(version(tag) for _, tag in candidates.values())
    suppressed = set()
    for digest, (proposal, tag) in candidates.items():
        if tag not in published:
            continue
        packet = proposal['payload']['packet']
        observed = packets.metadata(packet['reference'], packet['sha256'], 'scans.json', producer=packet['producer'])
        producer = dict(observed['producer'], repository=cfg['repository'],
                        revision=observed['producer'].get('revision', observed['revision']), sourceRevision=observed['revision'])
        common.require(observed.get('repository') == cfg['repository'] and producer == packet['producer']
                       and observed['revision'] == proposal['payload']['product']['revision'],
                       'Published observations differ from exact approved product and producer')
        expiry = scheduling.observation_expiry(observed, cfg)
        # Older published versions are historical recovery targets, not desired
        # periodic work. Their expiry was observed; explicit selection remains.
        if dt.datetime.now(dt.timezone.utc) < expiry or version(tag) < newest:
            suppressed.add(digest)
    return suppressed


def main():
    cli = common.parser(__doc__)
    cli.add_argument('--release-only', action='store_true')
    cli.add_argument('--proposal-hash')
    cli.add_argument('--admitted-release', action='store_true')
    cli.add_argument('--optional', action='store_true')
    cli.add_argument('--directory', type=Path, default=Path('candidate-evidence'))
    args = cli.parse_args()
    cfg = common.config(args.config, live=True)
    _, records = common.ledger(cfg)
    release_only = args.release_only or os.environ.get('DECISION_RELEASE_ONLY') == 'true'
    if args.admitted_release:
        common.require(release_only and isinstance(args.proposal_hash, str)
                       and common.HASH.fullmatch(args.proposal_hash)
                       and os.environ.get('PUBLICATION_METADATA_ONLY') == 'true',
                       'Admitted cache recovery requires exact metadata-only release selection')
        common.admitted_release(cfg, records, args.proposal_hash)
    releases = authority.collection(authority.github_api, f'repos/{cfg["repository"]}/releases') if release_only and not args.admitted_release else []
    published = {r['tag_name'] for r in releases if r.get('draft') is False and isinstance(r.get('tag_name'), str)}
    suppressed = current_published_products(cfg, records, published, args.proposal_hash) if release_only else set()
    try:
        open_proposals = {} if args.admitted_release else pending(cfg)
        digest, proposal = select(cfg, records, open_proposals, release_only, args.proposal_hash, suppressed_products=suppressed)
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
    metadata_only = os.environ.get('PUBLICATION_METADATA_ONLY') == 'true'
    if metadata_only:
        manifest = packets.metadata(packet['reference'], packet['sha256'], 'decision-packet.json', producer=packet.get('producer'))
        args.directory.mkdir(parents=True, exist_ok=False)
        names = ['scans.json', 'product.json', 'inputs.sha256', 'inventory/maestro-system.cdx.json',
                 'inventory/xen-orchestra-supply.cdx.json', 'inventory/Cargo.lock']
        if 'release-notes.md' in manifest['files']: names.append('release-notes.md')
        for name in names:
            path = args.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(packets.metadata_bytes(packet['reference'],packet['sha256'],name,producer=packet.get('producer')))
        args.directory.with_suffix('.source.json').write_text(json.dumps(packet))
    else:
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
        common.require((metadata_only and manifest['files'].get(name, {}).get('sha256') == expected)
                       or (path.is_file() and not path.is_symlink() and packets.file_hash(path) == expected),
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
