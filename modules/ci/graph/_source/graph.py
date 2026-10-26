#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate evaluated CI graphs and compare derivations. Scheduling remains shadow-only."""
import argparse
import hashlib
import json
from pathlib import Path
import re

SCHEMA = 1
SHA = re.compile(r'[a-f0-9]{40}')
DRV = re.compile(r'/nix/store/[a-z0-9]{32}-[^/\s]+\.drv')
OUT = re.compile(r'/nix/store/[a-z0-9]{32}-[^/\s]+')
PHASES = {'validation', 'media', 'evidence', 'publish'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def validate(graph):
    require(isinstance(graph, dict) and type(graph.get('schemaVersion')) is int
            and graph['schemaVersion'] == SCHEMA, 'Unknown graph version')
    require(graph.get('system') == 'x86_64-linux' and graph.get('mode') == 'shadow'
            and graph.get('gatingEnabled') is False, 'Graph gating has not passed hosted comparison')
    targets = graph.get('targets')
    require(isinstance(targets, dict) and targets, 'Missing graph targets')
    attributes, ordered = set(), []
    for key, target in targets.items():
        require(isinstance(target, dict) and target.get('id') == key, 'Invalid target identity')
        require(isinstance(target.get('owner'), str) and re.fullmatch(r'(features|ci|release)/[a-z0-9/-]+', target['owner']), 'Missing feature owner')
        require(target.get('attribute') not in attributes, 'Duplicate output ownership')
        attributes.add(target['attribute'])
        require(isinstance(target.get('derivation'), str) and DRV.fullmatch(target['derivation']), 'Missing derivation identity')
        require(isinstance(target.get('outputs'), dict) and target['outputs']
                and all(isinstance(v, str) and OUT.fullmatch(v) for v in target['outputs'].values()), 'Missing output identity')
        require(isinstance(target.get('phases'), list) and target['phases']
                and set(target['phases']) <= PHASES and len(set(target['phases'])) == len(target['phases']), 'Unknown obligation')
        require(isinstance(target.get('requirements'), list) and target['requirements']
                and set(target['requirements']) <= {'deterministic', 'verified-boot', 'producer-binding'}, 'Unknown validation requirements')
        require(isinstance(target.get('dependencies'), list) and len(set(target['dependencies'])) == len(target['dependencies'])
                and all(v in targets for v in target['dependencies']), 'Unmapped dependency')
    visiting, visited = set(), set()

    def visit(key):
        require(key not in visiting, 'Graph cycle')
        if key in visited:
            return
        visiting.add(key)
        for dep in targets[key]['dependencies']:
            visit(dep)
        visiting.remove(key)
        visited.add(key)
        ordered.append(key)
    for key in sorted(targets):
        visit(key)
    require(sum('validation' in t['phases'] for t in targets.values()) == 20, 'All twenty audit obligations are required')
    return ordered


def plan(candidate, base, revision, base_revision, changed_inputs=None, force=False, fork=False):
    require(bool(SHA.fullmatch(revision)), 'Immutable candidate revision required')
    reasons, changed, equal = [], [], []
    try:
        validate(candidate)
        require(bool(base_revision and SHA.fullmatch(base_revision)), 'Immutable base unavailable')
        validate(base)
        require(set(candidate['targets']) == set(base['targets']), 'Target set changed')
        for key, target in candidate['targets'].items():
            prior = base['targets'][key]
            (equal if (target['derivation'], target['outputs'], target['requirements']) ==
             (prior['derivation'], prior['outputs'], prior['requirements']) else changed).append(key)
        if changed_inputs is None or any(not path.startswith(('modules/', 'host/', 'docs/', '.github/'))
                                        and path not in {'flake.nix', 'flake.lock', 'devenv.nix', 'devenv.lock', 'devenv.yaml',
                                                         'secretspec.toml', 'README.md', 'CHANGELOG.md', 'AGENTS.md', 'VERSION', 'LICENSE', '.gitignore'}
                                        for path in changed_inputs):
            reasons.append('unmapped-inputs')
    except (ValueError, KeyError, TypeError) as error:
        reasons.append(str(error))
    if force:
        reasons.append('force-build')
    if fork:
        reasons.append('fork-restrictions')
    # Derivation equality explains potential cache reuse; it never grants retained
    # evidence, review authority, database freshness or permission to skip a test.
    return {'schemaVersion': SCHEMA, 'mode': 'shadow', 'gatingEnabled': False,
            'candidateRevision': revision, 'baseRevision': base_revision,
            'candidateGraphSha256': digest(candidate), 'baseGraphSha256': digest(base),
            'completeValidationRequired': True, 'fallbackReasons': reasons,
            'changedInputs': changed_inputs, 'changedDerivations': sorted(changed),
            'equalDerivations': sorted(equal), 'evidenceReuseAuthorized': False}


def ownership(graph):
    validate(graph)
    lines = ['<!-- Generated by maestro-ci-graph; do not edit. -->',
             '| Feature | Output | CI obligations |', '| --- | --- | --- |']
    for _, target in sorted(graph['targets'].items(), key=lambda row: (row[1]['owner'], row[1]['attribute'])):
        lines.append(f"| `{target['owner']}` | `{target['attribute']}` | {', '.join(target['phases'])} |")
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--base', type=Path)
    parser.add_argument('--revision')
    parser.add_argument('--base-revision')
    parser.add_argument('--changed-inputs', type=Path)
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--fork', action='store_true')
    parser.add_argument('--ownership', action='store_true')
    args = parser.parse_args()
    candidate = json.loads(args.candidate.read_text())
    if args.ownership:
        print(ownership(candidate), end='')
    elif args.revision:
        base = json.loads(args.base.read_text()) if args.base and args.base.is_file() else None
        inputs = args.changed_inputs.read_text().splitlines() if args.changed_inputs else None
        print(json.dumps(plan(candidate, base, args.revision, args.base_revision, inputs, args.force, args.fork), sort_keys=True, indent=2))
    else:
        validate(candidate)
        print(json.dumps({'schemaVersion': SCHEMA, 'graphSha256': digest(candidate), 'targets': len(candidate['targets'])}))


if __name__ == '__main__':
    main()
