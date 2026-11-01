#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authenticate a continuation scheduling hint; never grant decision authority."""
import json
import os
from pathlib import Path
import re

from decision_authority import github_api

REPOSITORY = 'closure-labs/maestro'
REPOSITORY_ID = 1127149753
WORKFLOW = '.github/workflows/release-continuation.yml'
RESOLVER = 'Resolve protected immutable release request'
FINAL = 'finalize / Prepare immutable official product for human approval'
CONTEXT = 'finalize / Bind authoritative release continuation context'
SECURITY = 'finalize / Verify and rescan release candidate'
SHA = re.compile(r'[0-9a-f]{40}')


def require(value):
    if not value:
        raise ValueError('Unverified continuation wakeup')


def positive(value):
    return type(value) is int and value > 0


def binding(run):
    return {key: run.get(key) for key in ('id', 'run_attempt', 'workflow_id', 'path',
            'repository', 'head_repository', 'head_sha', 'head_branch', 'event',
            'status', 'conclusion', 'referenced_workflows')}


def meaningful(api, event):
    """Use exact-attempt API jobs, not caller outputs or an artifact receipt.

    A proven skipped reusable job suppresses only its redundant wakeup. A real
    finalized product preserves the wakeup; all consumer evidence and authority
    verification still runs independently. Missing/ambiguous proof blocks this
    invocation; CI, security, release, schedule and manual wakeups are unchanged.
    """
    hint = event.get('workflow_run') or {}
    identity, attempt = hint.get('id'), hint.get('run_attempt')
    require(positive(identity) and positive(attempt))
    prefix = f'repos/{REPOSITORY}'
    endpoint = f'{prefix}/actions/runs/{identity}/attempts/{attempt}'
    run = api(endpoint)
    require(isinstance(run, dict))
    repo = {'id': REPOSITORY_ID, 'full_name': REPOSITORY}
    require(positive(run.get('id')) and positive(run.get('run_attempt'))
            and run['id'] == identity and run['run_attempt'] == attempt
            and positive(run.get('workflow_id')) and run.get('path') == WORKFLOW
            and all((run.get(key) or {}).get('id') == repo['id']
                    and (run.get(key) or {}).get('full_name') == repo['full_name']
                    for key in ('repository', 'head_repository'))
            and run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and run.get('head_branch') == 'main'
            and run.get('event') in ('workflow_run', 'workflow_dispatch')
            and isinstance(run.get('head_sha'), str) and SHA.fullmatch(run['head_sha']))
    workflow = api(f'{prefix}/actions/workflows/{run["workflow_id"]}')
    require(workflow.get('id') == run['workflow_id'] and workflow.get('path') == WORKFLOW
            and workflow.get('state') == 'active')
    branch = api(f'{prefix}/branches/main')
    current = (branch.get('commit') or {}).get('sha')
    require(branch.get('protected') is True and isinstance(current, str) and SHA.fullmatch(current))
    comparison = api(f'{prefix}/compare/{run["head_sha"]}...{current}?per_page=1')
    require((comparison.get('merge_base_commit') or {}).get('sha') == run['head_sha']
            and comparison.get('status') in ('ahead', 'identical'))
    require(run.get('referenced_workflows') == [{
        'path': f'{REPOSITORY}/.github/workflows/release.yml@{run["head_sha"]}',
        'sha': run['head_sha'], 'ref': 'refs/heads/main'}])
    inventory = api(endpoint + '/jobs?per_page=100')
    jobs = inventory.get('jobs')
    require(isinstance(jobs, list) and len(jobs) < 100
            and type(inventory.get('total_count')) is int
            and inventory['total_count'] == len(jobs))
    names, identities = {}, set()
    for job in jobs:
        require(isinstance(job, dict) and positive(job.get('id'))
                and job['id'] not in identities and positive(job.get('run_id'))
                and positive(job.get('run_attempt')) and job['run_id'] == identity
                and job['run_attempt'] == attempt and job.get('head_sha') == run['head_sha']
                and job.get('head_branch') == 'main' and job.get('status') == 'completed'
                and isinstance(job.get('name'), str) and job['name'] not in names)
        identities.add(job['id'])
        names[job['name']] = job['conclusion']
    require(names.get(RESOLVER) == 'success')
    if names == {RESOLVER: 'success', 'finalize': 'skipped'}:
        result = False
    else:
        require(all(names.get(name) == 'success' for name in (CONTEXT, SECURITY, FINAL)))
        result = True
    # Re-read this exact attempt. A later rerun is not substituted for the event.
    require(binding(api(endpoint)) == binding(run))
    return result


def main():
    require(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_run'
            and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.environ.get('GITHUB_REF') == 'refs/heads/main')
    result = meaningful(github_api, json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()))
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
        output.write('meaningful=' + str(result).lower() + '\n')
    print(json.dumps({'meaningful': result, 'authority': False}))


if __name__ == '__main__':
    from common import run
    raise SystemExit(run(main))
