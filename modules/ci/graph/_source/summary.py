#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Summarize observed CI jobs and raw Nix activities without granting authority."""
import datetime as dt
import json
import os
import re
from pathlib import Path
import subprocess


def activities(directory):
    builds, substitutes, incomplete = set(), set(), 0
    for path in Path(directory).rglob('*.jsonl'):
        complete = path.with_name(path.name + '.result.json')
        if not complete.is_file() or json.loads(complete.read_text()).get('exitCode') != 0:
            incomplete += 1
        with path.open() as stream:
            for line in stream:
                if not line.startswith('@nix '):
                    continue
                try:
                    value = json.loads(line[5:])
                except json.JSONDecodeError:
                    incomplete += 1
                    continue
                fields = value.get('fields')
                if value.get('action') == 'start' and isinstance(fields, list) and fields and isinstance(fields[0], str):
                    # Nix's stable native ActivityType values. These are observations,
                    # not assertions that a skipped test executed in this workflow.
                    if value.get('type') == 105 and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\s]+\.drv', fields[0]):
                        builds.add(fields[0])
                    elif value.get('type') == 108 and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\s]+', fields[0]):
                        substitutes.add(fields[0])
    return dict(buildDerivationsObserved=sorted(builds), substitutionPathsObserved=sorted(substitutes),
                incompleteOrFailedTraceCount=incomplete,
                interpretation='Observed native build/substitution activities; native plan results retain realization success.')


def summarize(pages, now):
    jobs = [job for page in pages for job in page['jobs']]
    rows = []
    for job in jobs:
        start, end = job.get('started_at'), job.get('completed_at')
        elapsed = None
        if start:
            start = dt.datetime.fromisoformat(start.replace('Z', '+00:00'))
            stop = dt.datetime.fromisoformat(end.replace('Z', '+00:00')) if end else now
            elapsed = round(max(0, (stop-start).total_seconds()), 3)
        rows.append(dict(name=job['name'], status=job['status'], conclusion=job.get('conclusion'),
                         elapsedSeconds=elapsed, completed=bool(end)))
    return rows


def main():
    repository = os.environ['GITHUB_REPOSITORY']
    run, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    error = None
    try:
        pages = json.loads(subprocess.check_output(['gh', 'api', '--paginate', '--slurp',
            f'repos/{repository}/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100'], text=True, timeout=45))
        jobs = summarize(pages, dt.datetime.now(dt.timezone.utc))
    except (subprocess.SubprocessError, ValueError, KeyError) as failure:
        jobs, error = [], type(failure).__name__

    native = activities('ci-observed')
    graph_path = Path('ci-graph/plan.json')
    graph = json.loads(graph_path.read_text()) if graph_path.is_file() else None
    route_path = Path('ci-graph/route.json')
    route = json.loads(route_path.read_text()) if route_path.is_file() else None
    qualification = route.get('qualification') if isinstance(route, dict) else None
    evidence = 'unavailable'
    if os.environ.get('RETAINED_REUSE') == 'true':
        evidence = 'verified-retained-complete'
    elif Path('ci-result.json').is_file():
        evidence = json.loads(Path('ci-result.json').read_text())['boot']['disposition']
    comparison_path = Path('ci-comparison/comparison.json')
    comparison = json.loads(comparison_path.read_text()) if comparison_path.is_file() else None
    result = dict(schemaVersion=1, candidateRevision=os.environ['GITHUB_SHA'], runId=run, runAttempt=attempt,
                  jobs=jobs, nixActivities=native, graph=graph, validationComparison=comparison,
                  plannedQualification=qualification, authorityClaim=False,
                  timingDiagnosticError=error, bootEvidenceDisposition=evidence)
    Path('ci-summary.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as out:
            out.write('### Observed CI results\n\n| Job | Result | Seconds |\n| --- | --- | --- |\n')
            for row in jobs:
                suffix = '' if row['completed'] else ' (elapsed; still running)'
                out.write(f"| {row['name']} | {row['conclusion'] or row['status']} | {row['elapsedSeconds']}{suffix} |\n")
            out.write(f"\nBoot evidence disposition: **{evidence}**. Timing API diagnostic: {error or 'available'}.\n")
            out.write(f"\nObserved source-build derivations: {len(native['buildDerivationsObserved'])}; substitution paths: {len(native['substitutionPathsObserved'])}. Failed or incomplete traces: {native['incompleteOrFailedTraceCount']}. Raw events and native realization manifests are retained. Skipped execution is never counted as a new test.\n")
            if qualification:
                out.write(f"\nNative plan selected **{qualification['mode']}**; media producer run "
                          f"`{qualification.get('media_run_id')}`; inventory producer run "
                          f"`{qualification.get('evidence_run_id')}`. These are planned selections, "
                          "not claims of newly executed tests; verification outcomes are recorded above.\n")
            if comparison:
                observations = comparison['nixActivities']
                out.write(f"\nSame-candidate audit comparison: **{comparison['status']}**, "
                          f"{comparison['targetCount']} exact obligations; graph-run native builds: "
                          f"{len(observations['buildDerivationsObserved'])}; substitution paths: "
                          f"{len(observations['substitutionPathsObserved'])}. Comparison observations never grant retained-evidence authority.\n")
            if graph:
                out.write(f"\nGraph mode: **{graph['mode']}**. Changed derivations: {len(graph['changedDerivations'])}; equal derivations: {len(graph['equalDerivations'])}. Fallback: {', '.join(graph['fallbackReasons']) or 'none'}.\n")
                out.write(f"\nChanged policies/identity contracts: {', '.join(graph.get('changedPolicies', [])) or 'none'}. "
                          f"Native qualification state regenerated: {graph.get('routeRegenerated', False)}.\n")


if __name__ == '__main__':
    main()
