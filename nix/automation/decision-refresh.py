#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rescan authenticated retained inputs using current trusted scanner code."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.environ.get('MAESTRO_DECISION_CORE', str(Path(__file__).with_name('decisions'))))
import common
from security_decisions import load_json


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_inputs(directory, native):
    inventory = directory / 'inventory'
    names = {'maestro-system.cdx.json', 'xen-orchestra-supply.cdx.json', 'Cargo.lock'}
    expected = native['evidence']
    hashes = directory / 'inputs.sha256'
    common.require(hashes.is_file() and not hashes.is_symlink()
                   and sha(hashes) == expected['inputHashes']['sha256']
                   and hashes.stat().st_size == expected['inputHashes']['size'],
                   'Original input checksum file differs from authenticated native evidence')
    identities = {}
    for line in hashes.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *](.+)', line)
        common.require(match is not None, 'Malformed original input checksum record')
        name = Path(match[2]).name
        common.require(name in names and name not in identities, 'Unexpected or duplicate native input')
        identities[name] = match[1]
    common.require(set(identities) == names, 'Incomplete retained native input bindings')
    for name, digest in identities.items():
        path = inventory / name
        common.require(path.is_file() and not path.is_symlink() and sha(path) == digest,
                       'Retained native inventory/lockfile identity mismatch: ' + name)
    system = inventory / 'maestro-system.cdx.json'
    common.require(sha(system) == expected['inventory']['sha256']
                   and system.stat().st_size == expected['inventory']['size'], 'Native inventory digest mismatch')
    return inventory


def path_identities(paths):
    raw = json.loads(common.command(['nix', 'path-info', '--json', *paths]))
    if isinstance(raw, dict):
        return {path: {'storePath': path, 'narHash': info['narHash']} for path, info in raw.items()}
    common.require(isinstance(raw, list), 'Invalid Nix path identity response')
    return {info['path']: {'storePath': info['path'], 'narHash': info['narHash']} for info in raw}


def distribution_cache():
    source = Path(os.environ.get('MAESTRO_DISTRIBUTION_CACHE_SOURCE', str(Path(__file__).with_name('distribution-cache.py'))))
    spec = importlib.util.spec_from_file_location('maestro_distribution_cache', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def realize(product, directory=None, transport=None):
    roots = {r['storePath']: {'storePath': r['storePath'], 'narHash': r['narHash']}
             for r in [*product['products'].values(), *product.get('roots', {}).values()]}
    if transport is not None:
        common.require(directory is not None, 'Authenticated transport directory required')
        distribution_cache().restore(directory, transport, list(roots.values()))
    missing = [path for path in roots if not Path(path).exists()]
    common.require(not missing, 'Retained closure is unavailable; authenticated distribution transport is required')
    common.require(path_identities(list(roots)) == roots, 'Realized retained closure NAR identity mismatch')


def main():
    source = Path(os.environ['DECISION_EVIDENCE_DIRECTORY']).resolve()
    output = Path(os.environ.get('SECURITY_OUTPUT', 'security-report')).resolve()
    root = Path(os.environ.get('MAESTRO_SYSTEM_ROOT', '.')).resolve()
    cfg = common.config(Path(os.environ.get('MAESTRO_DECISION_POLICY', str(root / 'nix/automation/decision-policy.json'))), live=True)
    # This authenticates historical identity ONLY. The expired document is never
    # submitted to admission or reissued with changed timestamps.
    old = common.scans(source / 'scans.json', cfg, allow_expired=True)
    original_product = common.product(source / 'product.json', cfg, old)
    common.require(set(old['profiles']) == {'maestro'}, 'Unexpected retained appliance profile')
    inventory = verify_inputs(source, old['profiles']['maestro'])
    common.require(output != source and output not in source.parents and source not in output.parents,
                   'Fresh output must be separate from retained evidence')
    realize(original_product, source, old.get('transport'))
    output.mkdir(parents=True, exist_ok=False)
    shutil.copytree(inventory, output / 'inventory')
    if 'transport' in old:
        for name in old['transport']['parts']:
            shutil.copyfile(source / name, output / name)
    environment = dict(os.environ, SECURITY_INVENTORY=str(output / 'inventory'), SECURITY_OUTPUT=str(output),
                       SECURITY_CARGO_LOCK=str(output / 'inventory/Cargo.lock'))
    subprocess.run(['maestro-ci-security-scan'], check=True, env=environment, timeout=3600)
    native = load_json(output / 'security-result.json')
    common.require(native.get('status') == 'complete' and native.get('scannerHealth') == 'healthy',
                   'Fresh scan did not complete with native health')
    old_subjects = old['profiles']['maestro']['subjects']
    common.require(native['subjects'] == old_subjects, 'Fresh native scan changed immutable closure subjects')
    current = os.environ['GITHUB_SHA']
    common.require(common.SHA.fullmatch(current), 'Immutable current producer revision required')
    scanned = common.timestamp(native['scannedAt'])
    now = dt.datetime.now(dt.timezone.utc)
    common.require(dt.timedelta() <= now - scanned < dt.timedelta(hours=1), 'Fresh native scan timestamp invalid')
    envelope = {'schema': 1, 'repository': cfg['repository'], 'revision': original_product['revision'],
                'producer': {'workflow': '.github/workflows/security.yml', 'runId': int(os.environ['GITHUB_RUN_ID']),
                             'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'revision': current},
                'scannedAt': scanned.isoformat(), 'expiresAt': (scanned + dt.timedelta(hours=24)).isoformat(),
                'profiles': {'maestro': native}}
    original_producer = dict(old.get('productProducer', old['producer']))
    original_producer.setdefault('revision', old['revision'])
    envelope['productProducer'] = original_producer
    if 'transport' in old:
        envelope['transport'] = old['transport']
    (output / 'scans.json').write_text(json.dumps(envelope, sort_keys=True, indent=2) + '\n')
    # Exact bytes retain the original source-revision provenance signature.
    shutil.copyfile(source / 'product.json', output / 'product.json')
    for name, digest in original_product['assets'].items():
        path = source / name
        common.require(path.is_file() and not path.is_symlink() and sha(path) == digest,
                       'Retained official release asset missing/mismatched')
        shutil.copyfile(path, output / name)
    common.emit({'schema': 1, 'status': 'rescanned', 'revision': envelope['revision'], 'directory': str(output)})


if __name__ == '__main__':
    sys.exit(common.run(main))
