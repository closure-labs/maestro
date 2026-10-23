#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch an immutable upstream XO handoff bound to the exact appliance input."""
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.environ.get('MAESTRO_DECISION_CORE', str(Path(__file__).with_name('decisions'))))
import common
import operations
import decision_packets as packets
import destinations
from decision_authority import github_api, document_at
from security_decisions import load_json, canonical_hash


def locked_revision(root, lock=None):
    lock = lock if lock is not None else load_json(root / 'flake.lock')
    reference = lock['nodes'][lock.get('root', 'root')]['inputs']['xen-orchestra-ce']
    common.require(isinstance(reference, str), 'XO flake input must have one explicit locked node')
    value = lock['nodes'][reference]['locked']
    common.require(value.get('type') == 'github' and value.get('owner') == 'closure-labs'
                   and value.get('repo') == 'xo-nixpkg' and common.SHA.fullmatch(value.get('rev', '')),
                   'Appliance XO input is not an exact official locked revision')
    return value['rev']


def runtime_context(directory):
    scans = load_json(directory / 'scans.json')
    native = scans['profiles']['maestro']
    inventory = directory / 'inventory/maestro-system.cdx.json'
    expected = native['evidence']['inventory']
    common.require(packets.file_hash(inventory) == expected['sha256'] and inventory.stat().st_size == expected['size'],
                   'XO runtime context inventory differs from authenticated native evidence')
    props = {p['name']: p['value'] for p in load_json(inventory)['properties']}
    context = json.loads(props['maestro:runtimeContext'])
    context_digest = hashlib.sha256(json.dumps(context, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    common.require(context_digest == native['runtimeContextDigest'] == props['maestro:runtimeContextDigest'],
                   'XO runtime context binding mismatch')
    return context, load_json(inventory).get('components', [])


def expected_channel(directory):
    context, _ = runtime_context(directory)
    channel = context['runtime'].get('xoChannel', 'latest')
    common.require(channel in ('latest', 'stable', 'rolling'), 'Invalid typed runtime XO channel')
    return 'xo-' + channel


def public_output(path):
    """Read one identity from the consumer's pinned cache set; never authorize."""
    common.require(destinations.STORE.fullmatch(path), 'Invalid actual runtime XO output')
    with operations.budget(90):
        for cache in ('https://maestro.cachix.org', 'https://xen-orchestra-ce.cachix.org',
                      'https://cache.nixos.org'):
            status, body = destinations.http(cache + '/' + Path(path).name[:32] + '.narinfo')
            if status == 404:
                continue
            common.require(status == 200, 'Pinned public cache metadata is unavailable')
            fields = {}
            for line in body.decode('utf-8').splitlines():
                key, separator, value = line.partition(': ')
                common.require(separator and (key not in fields or key == 'Sig'),
                               'Malformed actual XO cache metadata')
                fields[key] = value
            common.require(fields.get('StorePath') == path and fields.get('URL')
                           and re.fullmatch(r'[1-9][0-9]*', fields.get('NarSize', '')),
                           'Actual XO cache metadata differs from requested output')
            # Return the first observed identity. The exact checked handoff
            # policy below rejects a conflicting hash; never search past one.
            return {'storePath': path, 'narHash': destinations.nar_hash(fields.get('NarHash', ''))}
    raise ValueError('Actual XO output is missing from the pinned public cache set')


def actual_output(directory):
    context, components = runtime_context(directory)
    path = context['runtime']['xoPackage']
    common.require(isinstance(path, str) and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\s]+', path),
                   'Invalid actual runtime XO output')
    common.require(any(any(p.get('name') in ('nix:storePath', 'nix:output_path') and p.get('value') == path
                           for p in c.get('properties', [])) for c in components),
                   'Actual XO root is absent from complete local package inventory')
    if not Path(path).exists():
        return public_output(path)
    command = ['nix', 'path-info', '--json', path]
    info = json.loads(common.command(command, timeout=120))
    if isinstance(info, list):
        common.require(len(info) == 1 and info[0].get('path') == path, 'Ambiguous XO path identity')
        info = info[0]
    else:
        info = info[path]
    return {'storePath': path, 'narHash': info['narHash']}


def handoff_documents(source_policy, current_policy, profile):
    """Select fresh observations without changing the source-pinned product."""
    common.require(type(source_policy.get('schema')) is int and source_policy['schema'] == 1
                   and source_policy.get('mode') == 'official'
                   and type(current_policy.get('schema')) is int and current_policy['schema'] == 1,
                   'Invalid source or current handoff policy schema')
    def packet(policy):
        value = policy.get('packet', {})
        common.require(isinstance(value, dict) and set(value) == {'reference', 'sha256'}
                       and isinstance(value['reference'], str) and packets.REFERENCE.fullmatch(value['reference'])
                       and isinstance(value['sha256'], str) and common.HASH.fullmatch(value['sha256']),
                       'Immutable checked XO packet reference required')
        return value
    original = packet(source_policy)
    selected = original
    binding = ('repository', 'revision', 'channel', 'storePath', 'narHash')
    if (current_policy.get('mode') == 'official'
            and canonical_hash({key: current_policy.get(key) for key in binding})
            == canonical_hash({key: source_policy.get(key) for key in binding})):
        selected = packet(current_policy)
    if canonical_hash(selected) != canonical_hash(original):
        # The old packet remains the authenticated full-product identity. Its
        # old scans grant no admission: only the selected fresh packet below
        # reaches the unchanged attestation and live upstream gate.
        original_product = packets.decode_json(packets.metadata_bytes(
            original['reference'], original['sha256'], 'product.json'))
        product = packets.metadata_bytes(selected['reference'], selected['sha256'], 'product.json')
        common.require(canonical_hash(packets.decode_json(product))
                       == canonical_hash(original_product),
                       'Fresh handoff changes the immutable upstream product')
        documents = {'product.json': product}
        names = ('scans.json', 'handoff-' + profile + '.json')
    else:
        documents = {}
        names = ('scans.json', 'product.json', 'handoff-' + profile + '.json')
    documents.update({name: packets.metadata_bytes(selected['reference'], selected['sha256'], name)
                      for name in names})
    return documents


def materialize():
    root = Path(os.environ.get('MAESTRO_SYSTEM_ROOT', '.')).resolve()
    local = Path(os.environ['DECISION_EVIDENCE_DIRECTORY']).resolve()
    cfg = common.config(Path(os.environ.get('MAESTRO_DECISION_POLICY', str(root / 'nix/automation/decision-policy.json'))), live=True)
    scan = common.scans(local / 'scans.json', cfg)
    product = common.product(local / 'product.json', cfg, scan)
    policy_path = Path(os.environ.get('MAESTRO_XO_HANDOFF_POLICY', str(root / 'nix/automation/xo-handoff.json')))
    live_policy = load_json(policy_path)
    checked = document_at(github_api, cfg['repository'], 'nix/automation/xo-handoff.json', common.main_revision(cfg))
    common.require(canonical_hash(live_policy) == canonical_hash(checked)
                   and type(live_policy.get('schema')) is int and live_policy['schema'] == 1,
                   'Local handoff policy differs from checked main policy')
    common.require(live_policy.get('mode') in ('official', 'custom'),
                   'Current XO handoff policy is unconfigured; publication remains frozen')
    # A historical candidate carries its own checked immutable binding. The
    # binding is provenance only: enabled current policy and current upstream
    # admission below remain mandatory at the distribution boundary.
    policy = document_at(github_api, cfg['repository'], 'nix/automation/xo-handoff.json', product['revision'])
    common.require(type(policy.get('schema')) is int and policy['schema'] == 1,
                   'Invalid candidate-source handoff binding')
    mode = policy.get('mode')
    common.require(mode in ('official', 'custom'), 'XO handoff binding is unconfigured; publication remains frozen')
    identity = actual_output(local)
    if mode == 'custom':
        # Independent appliance inventory/scanning remains mandatory. This
        # classification confers no upstream or downstream risk approval.
        common.require(scan['profiles']['maestro'].get('status') == 'complete'
                       and scan['profiles']['maestro'].get('scannerHealth') == 'healthy', 'Custom XO needs complete local native evidence')
        common.emit({'schema': 1, 'status': 'local-evidence-only', 'product': identity,
                     'note': 'Custom package requires independent appliance admission; no upstream approval claimed.'})
        return
    # Historical recovery uses the exact candidate-source lock as data; it
    # never checks out or evaluates historical workflow/package code.
    source_lock = document_at(github_api, cfg['repository'], 'flake.lock', product['revision'])
    revision = locked_revision(root, source_lock)
    profile = expected_channel(local)
    common.require(policy.get('repository') == 'closure-labs/xo-nixpkg' and policy.get('revision') == revision
                   and policy.get('channel') == profile and policy.get('storePath') == identity['storePath']
                   and policy.get('narHash') == identity['narHash'], 'Handoff policy differs from locked actual runtime XO package')
    upstream_token = os.environ.get('XO_AUTHORITY_TOKEN')
    common.require(isinstance(upstream_token, str) and upstream_token.strip(),
                   'Repository-scoped XO_AUTHORITY_TOKEN is required for live upstream authority')
    # All Maestro metadata checks are complete. Only this helper process and
    # its upstream gh children receive the separately scoped read credential.
    os.environ['GH_TOKEN'] = upstream_token
    upstream = {'repository': 'closure-labs/xo-nixpkg'}
    main = common.main_revision(upstream)
    upstream_policy = document_at(github_api, upstream['repository'], 'ci/decision-policy.json', main)
    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        config_path = temporary / 'upstream-policy.json'
        config_path.write_text(json.dumps(upstream_policy))
        upstream = common.config(config_path, live=True, enabled=True)
        # XO publishes handoffs in its dedicated product packet repository;
        # security decisions remain in the distinct -decisions repository.
        packets.REGISTRY = 'ghcr.io/closure-labs/xo-nixpkg-products'
        packets.REFERENCE = re.compile(re.escape(packets.REGISTRY) + r'@sha256:[0-9a-f]{64}')
        fetched = temporary / 'packet'
        fetched.mkdir()
        for name, data in handoff_documents(policy, live_policy, profile).items():
            (fetched/name).write_bytes(data)
        command = [sys.executable, str(Path(common.__file__).with_name('handoff.py')), '--config', str(config_path),
                   '--handoff', str(fetched / ('handoff-' + profile + '.json')), '--directory', str(fetched),
                   '--expected-revision', revision, '--expected-channel', profile,
                   '--expected-store-path', identity['storePath'], '--expected-nar-hash', identity['narHash']]
        result = json.loads(common.command(command, timeout=900))
    common.emit(result)


def main():
    with operations.budget(900):
        return materialize()


if __name__ == '__main__':
    sys.exit(common.run(main))
