# SPDX-License-Identifier: Apache-2.0
"""Keep one existing required CodeQL context pending until this attempt is authorized."""
import json
import os
import re
import time

import decision_authority as authority
import codeql_findings as findings

APP_ID = 5384448
CHECK = 'Maintainer decision authority'
MARKER = re.compile(r'\n<!-- maestro-codeql-receipt (\{[^\n]+\}) -->$')


def latest_check(api, repository, sha):
    value = api(f'repos/{repository}/commits/{sha}/check-runs?check_name=Maintainer%20decision%20authority&filter=all&per_page=100')
    runs = value.get('check_runs') if isinstance(value, dict) else None
    findings.require(isinstance(runs, list) and type(value.get('total_count')) is int
                     and len(runs) == value['total_count'] and len(runs) <= 100,
                     'incomplete authority check inventory')
    matches = [check for check in runs if isinstance(check, dict)
               and check.get('name') == CHECK and check.get('app', {}).get('id') == APP_ID]
    for check in matches:
        findings.require(type(check.get('id')) is int and check['id'] > 0 and check.get('head_sha') == sha,
                         'invalid App check identity')
    return max(matches, key=lambda check: check['id']) if matches else None


def receipt(check, repository, sha, run_id, attempt):
    if not check or check.get('status') != 'completed' or check.get('conclusion') != 'success':
        return None
    summary = check.get('output', {}).get('summary')
    if not isinstance(summary, str) or len(summary) > 65536:
        return None
    match = MARKER.search(summary)
    if not match:
        return None
    value = json.loads(match[1], object_pairs_hook=findings.unique_object)
    fields = {'schema', 'repository', 'target', 'head', 'pullRequest', 'run', 'attempt',
              'digest', 'artifacts', 'reviewsSha256'}
    findings.require(isinstance(value, dict) and type(value.get('schema')) is int
                     and ((value['schema'] == 1 and set(value) == fields)
                          or (value['schema'] == 2 and set(value) == fields | {'acceptance'})),
                     'invalid authority receipt shape')
    if value.get('run') != run_id or value.get('attempt') != attempt:
        return None  # A same-SHA earlier run/attempt never releases this verdict.
    findings.require(type(value['schema']) is int and value['schema'] in (1, 2)
                     and value['repository'] == repository and value['target'] == sha
                     and type(value['run']) is int and type(value['attempt']) is int
                     and type(value['pullRequest']) is int and value['pullRequest'] > 0
                     and isinstance(value['head'], str) and authority.SHA.fullmatch(value['head'])
                     and all(isinstance(value[k], str) and re.fullmatch(r'[0-9a-f]{64}', value[k])
                             for k in ('digest', 'reviewsSha256'))
                     and check.get('external_id') == f'codeql-v1:{run_id}:{attempt}:{value["digest"]}',
                     'authority receipt identity mismatch')
    return value


def verify_acceptance(api, repository, record):
    if record['schema'] == 2:
        findings.verify_acceptance(api, repository, record['pullRequest'], record['head'],
                                   record['digest'], record['acceptance'])


def verify(api, repository, sha, run_id, attempt, event):
    check = latest_check(api, repository, sha)
    record = receipt(check, repository, sha, run_id, attempt)
    if record is None:
        return False
    run = findings.latest_run(api, repository, sha, event)
    findings.require((run['id'], run['run_attempt']) == (run_id, attempt), 'a newer scan superseded this verdict')
    pull = api(f'repos/{repository}/pulls/{record["pullRequest"]}')
    findings.require(pull.get('state') == 'open' and pull.get('base', {}).get('ref') == 'main'
                     and pull.get('base', {}).get('repo', {}).get('full_name') == repository
                     and pull.get('head', {}).get('sha') == record['head'], 'PR changed since authority decision')
    if event == 'pull_request':
        findings.require(record['head'] == sha, 'PR scan head mismatch')
    else:
        branch_name = run.get('head_branch')
        findings.require(isinstance(branch_name, str) and
                         re.fullmatch(r'gh-readonly-queue/main/pr-' + str(record['pullRequest']) + r'-[0-9a-f]{7,40}', branch_name),
                         'invalid live queue receipt identity')
        branch = api(f'repos/{repository}/git/ref/heads/{branch_name}')
        findings.require(branch.get('object', {}).get('sha') == sha, 'queue ref changed since authority decision')
    if findings.review_snapshot(api, repository, record['pullRequest']) != record['reviewsSha256']:
        return False  # Wait for fresh App evaluation of dismissal/edits/new reviews.
    verify_acceptance(api, repository, record)
    findings.require(findings.artifact_snapshot(api, repository, run_id, attempt, sha) == record['artifacts'],
                     'analysis reports changed since authority decision')
    newest = latest_check(api, repository, sha)
    if not newest or newest.get('id') != check['id'] or newest.get('conclusion') != 'success':
        return False
    # Recheck the run after all dependent API reads; failed/cancelled scans or
    # rerun-attempt races can never reuse this proof.
    final = findings.latest_run(api, repository, sha, event)
    findings.require((final['id'], final['run_attempt']) == (run_id, attempt), 'analysis changed before verdict')
    verify_acceptance(api, repository, record)
    return findings.review_snapshot(api, repository, record['pullRequest']) == record['reviewsSha256']


def require_current_run(current, repository, sha, run_id, attempt, event):
    """Keep identity and lifecycle failures distinguishable without logging API bodies."""
    findings.require(isinstance(current, dict), 'invalid verdict run response')
    source = current.get('repository')
    identities = {
        'id': current.get('id') == run_id,
        'attempt': current.get('run_attempt') == attempt,
        'head': current.get('head_sha') == sha,
        'event': current.get('event') == event,
        'repository': isinstance(source, dict) and source.get('full_name') == repository,
    }
    mismatches = ','.join(name for name, matches in identities.items() if not matches)
    findings.require(not mismatches, 'verdict run identity mismatch: ' + mismatches)
    status, conclusion = current.get('status'), current.get('conclusion')
    # Report only fixed vocabulary, never arbitrary response text or credentials.
    safe_status = status if status in ('queued', 'requested', 'waiting', 'pending',
                                      'in_progress', 'completed') else 'unknown'
    safe_conclusion = conclusion if conclusion in ('success', 'failure', 'cancelled',
                                                  'timed_out', 'neutral', 'skipped',
                                                  'action_required', 'stale', 'startup_failure') else 'none-or-unknown'
    findings.require(status in ('in_progress', 'completed')
                     and (status != 'completed' or conclusion == 'success'),
                     f'verdict run lifecycle rejected: status={safe_status}; conclusion={safe_conclusion}')


def wait(api, repository, sha, run_id, attempt, event, *, seconds=4800, clock=time.monotonic, sleep=time.sleep):
    findings.require(repository == 'closure-labs/maestro' and authority.SHA.fullmatch(sha)
                     and type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
                     'invalid in-run verdict context')
    findings.require(event in ('pull_request', 'merge_group', 'push', 'schedule', 'workflow_dispatch'),
                     'unsupported verdict event')
    if event not in ('pull_request', 'merge_group'):
        # Protected-main scans publish SARIF, but do not invent a PR approval.
        findings.require(os.environ.get('GITHUB_REF') == 'refs/heads/main', 'protected main required')
        run = findings.wait_for_analysis(api, repository, sha, event)
        findings.require((run['id'], run['run_attempt']) == (run_id, attempt), 'main scan identity changed')
        return
    deadline = clock() + seconds
    while True:
        current = api(f'repos/{repository}/actions/runs/{run_id}')
        require_current_run(current, repository, sha, run_id, attempt, event)
        try:
            findings.scan_jobs(api, repository, current)
        except findings.AnalysisPending:
            pass
        if verify(api, repository, sha, run_id, attempt, event):
            return
        findings.require(clock() < deadline, 'timed out awaiting exact findings approval; rerun all CodeQL jobs after approval')
        sleep(min(30, max(0, deadline - clock())))


def main():
    print('Waiting for this exact scan attempt and its Maintainer decision authority review; no earlier green check is reusable.', flush=True)
    wait(authority.github_api, os.environ['GITHUB_REPOSITORY'], os.environ['CODEQL_TARGET_SHA'],
         int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT']), os.environ['GITHUB_EVENT_NAME'])
    print('Exact current-attempt CodeQL findings authority verified.')


if __name__ == '__main__':
    main()
