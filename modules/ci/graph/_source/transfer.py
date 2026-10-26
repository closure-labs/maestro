#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Digest-bound, same-attempt transport of exact evaluated outputs; never rebuilds."""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from graph import digest, require


def command(*args):
    return subprocess.check_output(args, text=True, timeout=1800).strip()


def producer():
    value = {key: os.environ[key] for key in ['GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']}
    require(re.fullmatch('[a-f0-9]{40}', value['GITHUB_SHA']), 'Immutable candidate required')
    require(all(re.fullmatch('[1-9][0-9]*', value[k]) for k in ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']), 'Exact workflow attempt required')
    return value


def bindings(graph, plan, plan_sha):
    require(re.fullmatch('[a-f0-9]{64}', plan_sha or ''), 'Missing authenticated plan digest')
    require(__import__('hashlib').sha256(plan.read_bytes()).hexdigest() == plan_sha, 'Plan digest mismatch')
    expected = json.loads(plan.read_text())
    require(expected['candidateRevision'] == producer()['GITHUB_SHA']
            and expected['candidateGraphSha256'] == digest(graph), 'Graph differs from planned candidate')
    return expected


def validate(manifest, phase, expected, graph_hash):
    require(isinstance(manifest, dict) and set(manifest) == {'schemaVersion', 'phase', 'producer', 'graphSha256', 'targets', 'roots', 'transport', 'files', 'evidenceFiles', 'isoSha256'}, 'Incomplete transfer manifest')
    require(type(manifest['schemaVersion']) is int and manifest['schemaVersion'] == 2, 'Unknown transfer schema')
    require(manifest['phase'] == phase and manifest['producer'] == producer(), 'Changed transfer producer or attempt')
    require(manifest['graphSha256'] == graph_hash and manifest['targets'] == expected, 'Changed derivation binding')
    outputs = {value for target in expected for value in target['outputs'].values()}
    require(len({root['storePath'] for root in manifest['roots']}) == len(manifest['roots'])
            and {root['storePath'] for root in manifest['roots']} == outputs, 'Missing or conflicting output identities')
    require(isinstance(manifest['files'], dict) and set(manifest['files']) == set(INDEX_FILES[phase]), 'Incomplete native index bindings')
    require(isinstance(manifest['evidenceFiles'], dict) and set(manifest['evidenceFiles']) == (set(EVIDENCE_FILES) if phase == 'inventory' else set()), 'Incomplete inventory evidence bindings')
    require(all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v) for v in [*manifest['files'].values(), *manifest['evidenceFiles'].values()]), 'Invalid bound metadata digest')
    require(manifest['isoSha256'] is None or (isinstance(manifest['isoSha256'], str) and re.fullmatch('[a-f0-9]{64}', manifest['isoSha256'])), 'Invalid ISO byte binding')
    return manifest


INDEX_FILES = {
    'appliance': ['evidence.json', 'publish.json', 'evidence.timings.json', 'publish.timings.json'],
    'installer': ['media.json', 'media.timings.json'],
    'inventory': [],
}
EVIDENCE_FILES = [name + suffix for name in ['maestro-system.spdx.json', 'maestro-system.cdx.json',
    'xen-orchestra-supply.assertion.json', 'xen-orchestra-supply.spdx.json', 'xen-orchestra-supply.cdx.json']
    for suffix in ['', '.sha256']]


def file_digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_files(directory, expected):
    for name, identity in expected.items():
        require(Path(name).name == name, 'Unsafe bound metadata filename')
        path = Path(directory) / name
        require(path.is_file() and not path.is_symlink() and file_digest(path) == identity,
                'Missing or corrupt bound metadata: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['export', 'restore', 'verify'])
    parser.add_argument('phase', choices=['appliance', 'installer', 'inventory'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--graph', type=Path, default=Path('ci-graph/candidate.json'))
    parser.add_argument('--plan', type=Path, default=Path('ci-graph/plan.json'))
    args = parser.parse_args()
    graph = json.loads(args.graph.read_text())
    bindings(graph, args.plan, os.environ.get('GRAPH_PLAN_SHA256'))
    expected = graph['transport'][args.phase]
    path = args.directory / 'manifest.json'
    spec = importlib.util.spec_from_file_location('distribution_cache', os.environ['MAESTRO_DISTRIBUTION_CACHE_SOURCE'])
    transfer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transfer)
    if args.action == 'export':
        paths = sorted({value for target in expected for value in target['outputs'].values()})
        records = json.loads(command('nix', 'path-info', '--json', *paths))
        if isinstance(records, list):
            records = {record['path']: record for record in records}
        require(set(records) == set(paths), 'Unrealized planned outputs')
        roots = [{'storePath': key, 'narHash': records[key]['narHash']} for key in paths]
        args.directory.mkdir(parents=True, exist_ok=True)
        files = {name: file_digest(args.directory / name) for name in INDEX_FILES[args.phase]}
        evidence = {}
        iso_digest = None
        if args.phase == 'inventory':
            evidence_root = Path(os.environ.get('SECURITY_INVENTORY', '.'))
            evidence = {name: file_digest(evidence_root / name) for name in EVIDENCE_FILES}
            iso = Path('result-installer/iso/maestro-installer.iso')
            if iso.is_file():
                iso_digest = file_digest(iso)
        manifest = dict(schemaVersion=2, phase=args.phase, producer=producer(), graphSha256=digest(graph),
                        targets=expected, roots=roots, transport=transfer.export(args.directory, roots),
                        files=files, evidenceFiles=evidence, isoSha256=iso_digest)
        validate(manifest, args.phase, expected, digest(graph))
        path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        manifest_sha = transfer.digest(path)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('manifest_sha256=' + manifest_sha + '\n')
        print(manifest_sha)
    else:
        require(re.fullmatch('[a-f0-9]{64}', os.environ.get('TRANSFER_MANIFEST_SHA256', '')), 'Missing producer manifest digest')
        require(transfer.digest(path) == os.environ['TRANSFER_MANIFEST_SHA256'], 'Transfer manifest digest mismatch')
        manifest = validate(json.loads(path.read_text()), args.phase, expected, digest(graph))
        transfer.validate_manifest(args.directory, manifest['transport'])
        verify_files(args.directory, manifest['files'])
        if args.action == 'verify' and args.phase == 'inventory':
            verify_files(Path(os.environ.get('SECURITY_INVENTORY', '.')), manifest['evidenceFiles'])
        if args.action == 'restore':
            # Artifact digest and direct needs output authenticate this same run's
            # producer. Cross-run reuse uses the existing attestation verifier.
            transfer.restore(args.directory, manifest['transport'], manifest['roots'])
        print(json.dumps({'status': 'verified', 'phase': args.phase, 'roots': len(manifest['roots'])}))


if __name__ == '__main__':
    main()
