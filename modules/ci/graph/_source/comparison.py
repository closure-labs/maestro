#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare the complete audit with exact graph-driven realizations of its obligations."""
import argparse
import json
import math
import os
from pathlib import Path
import subprocess
import time

from graph import digest, require, validate
from transfer import bindings, producer, file_digest
from summary import activities


def validation_targets(graph):
    order = validate(graph)
    return [(key, graph['targets'][key]) for key in order
            if 'validation' in graph['targets'][key]['phases']]


def validate_audit(audit, graph):
    targets = {target['attribute']: target for _, target in validation_targets(graph)}
    require(audit.get('schemaVersion') == 2 and type(audit['schemaVersion']) is int
            and audit.get('plan') == 'maestro-validation'
            and type(audit.get('targetCount')) is int and audit['targetCount'] == 20
            and type(audit.get('failureCount')) is int and audit['failureCount'] == 0,
            'Incomplete complete-validation manifest')
    results = audit.get('results')
    require(isinstance(results, list) and len(results) == len(targets), 'Missing audit obligation')
    seen = set()
    for row in results:
        attribute = row.get('attribute')
        require(attribute in targets and attribute not in seen, 'Unknown or duplicate audit obligation')
        seen.add(attribute)
        target = targets[attribute]
        outputs = row.get('outputs')
        require(row.get('status') == 'success' and row.get('name') == target['name']
                and isinstance(outputs, list) and len(outputs) == len(set(outputs))
                and set(outputs) == set(target['outputs'].values()), 'Audit output differs from evaluated graph')
    return results


def read_bound_reference(directory, graph, plan_sha, expected_sha):
    path = directory / 'reference.json'
    require(file_digest(path) == expected_sha, 'Complete-validation reference digest mismatch')
    reference = json.loads(path.read_text())
    require(reference.get('schemaVersion') == 1 and type(reference['schemaVersion']) is int
            and reference.get('producer') == producer(), 'Changed complete-validation producer or attempt')
    require(reference.get('graphSha256') == digest(graph) and reference.get('planSha256') == plan_sha,
            'Complete validation used different graph or plan')
    for filename, field in [('audit.json', 'auditSha256'), ('timings.json', 'timingsSha256')]:
        require(file_digest(directory / filename) == reference.get(field), 'Changed complete-validation ' + filename)
    audit = json.loads((directory / 'audit.json').read_text())
    validate_audit(audit, graph)
    return reference, audit


def validate_timings(value, graph):
    require(value.get('schemaVersion') == 1 and type(value['schemaVersion']) is int
            and value.get('plan') == 'maestro-validation', 'Invalid baseline timing schema')
    expected = {t['attribute'] for _, t in validation_targets(graph)}
    rows = value.get('results')
    require(isinstance(rows, list) and len(rows) == len(expected), 'Missing baseline timings')
    seen = set()
    for row in rows:
        attribute, elapsed = row.get('attribute'), row.get('elapsedSeconds')
        require(attribute in expected and attribute not in seen and row.get('status') == 'success'
                and type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0,
                'Invalid or conflicting baseline timing')
        seen.add(attribute)
    return rows


def canonical_store_path(value):
    require(isinstance(value, str), 'Missing evaluated store path')
    return value if value.startswith('/nix/store/') else '/nix/store/' + value


def derivation_records(value):
    # Determinate Nix's v4 JSON uses basenames and a versioned envelope; older
    # supported native Nix uses absolute keys without the envelope.
    if 'derivations' in value:
        require(value.get('version') == 4, 'Unknown derivation JSON envelope')
        value = value['derivations']
    require(isinstance(value, dict), 'Invalid evaluated derivation records')
    return {canonical_store_path(key): row for key, row in value.items()}


def verify_recipes(targets, records):
    for _, target in targets:
        require(target['derivation'] in records, 'Missing evaluated derivation recipe')
        recipe = records[target['derivation']]
        actual = {name: canonical_store_path(row.get('path')) for name, row in recipe['outputs'].items()}
        require(actual == target['outputs'], 'Derivation recipe differs from graph output identities')


def validate_realization(records, target):
    require(isinstance(records, list) and len(records) == 1, 'Missing or conflicting realization')
    row = records[0]
    require(row.get('drvPath') == target['derivation'] and row.get('outputs') == target['outputs'],
            'Realized a different derivation or output')
    return sorted(row['outputs'].values())


def validate_comparison(value, graph, plan_sha, expected_producer):
    require(value.get('schemaVersion') == 1 and type(value['schemaVersion']) is int
            and value.get('status') == 'matched' and value.get('producer') == expected_producer,
            'Incomplete or changed comparison producer')
    require(value.get('graphSha256') == digest(graph) and value.get('planSha256') == plan_sha
            and value.get('gatingEnabled') is False and value.get('retainedEvidenceReuseAuthorized') is False,
            'Comparison differs from current graph or claims unauthorized reuse')
    targets = {key: target for key, target in validation_targets(graph)}
    rows = value.get('graphResults')
    require(type(value.get('targetCount')) is int and value['targetCount'] == 20
            and isinstance(rows, list) and len(rows) == 20, 'Missing comparison obligations')
    seen = set()
    for row in rows:
        key = row.get('id')
        require(key in targets and key not in seen, 'Unknown or duplicate comparison obligation')
        seen.add(key)
        target = targets[key]
        require(row.get('attribute') == target['attribute'] and row.get('derivation') == target['derivation']
                and row.get('status') == 'realized' and row.get('outputs') == sorted(target['outputs'].values()),
                'Comparison output differs from planned obligation')
    return value


def nix_json(*args, timeout=5400):
    return json.loads(subprocess.check_output(['nix', *args], text=True, timeout=timeout))


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def output_digest(path):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('manifest_sha256=' + file_digest(path) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['reference', 'compare'])
    args = parser.parse_args()
    os.chdir(os.environ.get('MAESTRO_SYSTEM_ROOT', os.getcwd()))
    graph = json.loads(Path('ci-graph/candidate.json').read_text())
    plan_sha = os.environ['GRAPH_PLAN_SHA256']
    bindings(graph, Path('ci-graph/plan.json'), plan_sha)
    targets = validation_targets(graph)
    if args.operation == 'reference':
        directory = Path(os.environ['MAESTRO_AUDIT_DIRECTORY'])
        validate_audit(json.loads((directory / 'audit.json').read_text()), graph)
        validate_timings(json.loads((directory / 'timings.json').read_text()), graph)
        reference = dict(schemaVersion=1, producer=producer(), graphSha256=digest(graph), planSha256=plan_sha,
                         auditSha256=file_digest(directory / 'audit.json'),
                         timingsSha256=file_digest(directory / 'timings.json'))
        path = directory / 'reference.json'
        write_json(path, reference)
        output_digest(path)
        return

    started = time.monotonic()
    reference, audit = read_bound_reference(Path('complete-audit'), graph, plan_sha,
                                            os.environ['AUDIT_REFERENCE_SHA256'])
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == producer()['GITHUB_SHA'],
            'Checkout differs from immutable candidate')
    root = Path.cwd()
    flake = f'git+file:{root}?shallow=1&rev={producer()["GITHUB_SHA"]}'
    current = nix_json('eval', '--accept-flake-config', '--no-write-lock-file', '--json',
                       flake + '#lib.ciGraph.x86_64-linux', timeout=900)
    require(digest(current) == digest(graph), 'Current evaluation differs from planned graph')
    recipes = derivation_records(nix_json('derivation', 'show',
        *sorted({target['derivation'] for _, target in targets}), timeout=900))
    verify_recipes(targets, recipes)
    directory = Path('ci-comparison')
    directory.mkdir(exist_ok=True)
    events = directory / 'nix-events'
    os.environ['MAESTRO_NIX_EVENTS_DIR'] = str(events.resolve())
    rows = []
    baseline = {row['attribute']: row for row in audit['results']}
    for key, target in targets:
        begin = time.monotonic()
        records = nix_json('build', '--accept-flake-config', '--no-link', '--json',
                           target['derivation'] + '^*')
        outputs = validate_realization(records, target)
        require(set(outputs) == set(baseline[target['attribute']]['outputs']), 'Graph/full result discrepancy')
        rows.append(dict(id=key, attribute=target['attribute'], derivation=target['derivation'],
                         outputs=outputs, status='realized', elapsedSeconds=round(time.monotonic()-begin, 3)))
        # Interrupted work must leave a partial diagnostic, never a success receipt.
        write_json(directory / 'partial.json', dict(schemaVersion=1, status='incomplete', results=rows))
    require(len(list(events.glob('*.jsonl'))) >= len(rows), 'Missing native comparison traces')
    observations = activities(events)
    require(observations['incompleteOrFailedTraceCount'] == 0, 'Incomplete or failed comparison realization trace')
    timing = json.loads(Path('complete-audit/timings.json').read_text())
    validate_timings(timing, graph)
    result = dict(schemaVersion=1, status='matched', producer=producer(), graphSha256=digest(graph),
                  planSha256=plan_sha, referenceSha256=os.environ['AUDIT_REFERENCE_SHA256'],
                  completeAuditSha256=reference['auditSha256'], targetCount=len(rows),
                  baselineTimings=timing['results'], graphResults=rows, nixActivities=observations,
                  elapsedSeconds=round(time.monotonic()-started, 3),
                  scope='complete-audit-versus-exact-graph-realization',
                  gatingEnabled=False, retainedEvidenceReuseAuthorized=False)
    path = directory / 'comparison.json'
    validate_comparison(result, graph, plan_sha, producer())
    write_json(path, result)
    output_digest(path)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write('### Same-candidate audit comparison\n\n')
            stream.write(f'All {len(rows)} obligations matched exact graph derivations and full-audit outputs. '
                         'No checks were omitted. Selective media/evidence scheduling remains disabled.\n\n')
            stream.write('| Obligation | Full seconds | Graph seconds |\n| --- | ---: | ---: |\n')
            full_times = {row['attribute']: row['elapsedSeconds'] for row in timing['results']}
            for row in rows:
                stream.write(f"| `{row['attribute']}` | {full_times[row['attribute']]} | {row['elapsedSeconds']} |\n")
            stream.write(f"\nObserved graph-run builds: {len(observations['buildDerivationsObserved'])}; "
                         f"substitution paths: {len(observations['substitutionPathsObserved'])}. "
                         'These are realization observations, not claims of newly executed tests or a speedup.\n')


if __name__ == '__main__':
    main()
