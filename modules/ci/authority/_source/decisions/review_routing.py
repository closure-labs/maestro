# SPDX-License-Identifier: Apache-2.0
"""Verified review wakeup routing; never an authorization or response cache."""
import re

COLLECTOR = '.github/workflows/decision-events.yml'
SHA = re.compile(r'[0-9a-f]{40}')


def binding(run):
    return {key: run.get(key) for key in ('id', 'run_attempt', 'event', 'path', 'workflow_id',
            'repository', 'head_repository', 'head_sha', 'head_branch', 'status', 'conclusion',
            'actor', 'triggering_actor')}


def review_target(api, repository, run, run_id):
    """Return one canonical live PR, or None to retain the global fallback.

    Only GitHub API metadata participates: no collector artifact, event body,
    branch-name convention, author claim or candidate code is trusted. The
    exact commit association, repository IDs, source branch and fresh PR must
    all agree. Legacy, fork, capped and ambiguous associations remain global.
    Transport/permission errors propagate rather than granting narrower work.
    """
    repo = run.get('repository') or {}
    head_repo = run.get('head_repository') or {}
    if (run.get('event') != 'pull_request_review' or run.get('path') != COLLECTOR
            or type(run_id) is not int or run_id < 1 or run.get('id') != run_id
            or type(run.get('run_attempt')) is not int or run['run_attempt'] < 1
            or type(run.get('workflow_id')) is not int or run['workflow_id'] < 1
            or run.get('status') != 'completed' or run.get('conclusion') != 'success'
            or repo.get('full_name') != repository or type(repo.get('id')) is not int or repo['id'] < 1
            or head_repo.get('id') != repo['id'] or head_repo.get('full_name') != repository
            or not isinstance(run.get('head_sha'), str) or not SHA.fullmatch(run['head_sha'])
            or not isinstance(run.get('head_branch'), str) or not run['head_branch']):
        return None
    initial = binding(run)
    prefix = 'repos/' + repository
    workflow = api(f'{prefix}/actions/workflows/{run["workflow_id"]}')
    if (not isinstance(workflow, dict) or workflow.get('id') != run['workflow_id']
            or workflow.get('path') != COLLECTOR or workflow.get('state') != 'active'):
        return None
    associated = api(f'{prefix}/commits/{run["head_sha"]}/pulls?per_page=100&page=1')
    # Narrow only a unique canonical association. Multiple/historical matches,
    # malformed or capped inventories fall back without per-candidate fanout.
    if not isinstance(associated, list) or len(associated) != 1:
        return None
    item = associated[0]
    number = item.get('number') if isinstance(item, dict) else None
    if type(number) is not int or number < 1:
        return None
    pull = api(f'{prefix}/pulls/{number}')
    if not isinstance(pull, dict):
        return None
    head, base = pull.get('head') or {}, pull.get('base') or {}
    source, target = head.get('repo') or {}, base.get('repo') or {}
    if not (pull.get('number') == number and pull.get('state') == 'open'
            and base.get('ref') == 'main' and target.get('id') == repo['id']
            and target.get('full_name') == repository
            and source.get('id') == head_repo['id'] and source.get('full_name') == repository
            and head.get('sha') == run['head_sha'] and head.get('ref') == run['head_branch']):
        return None
    # A rerun/head/workflow race discards routing, never later authority reads.
    current = api(f'{prefix}/actions/runs/{run_id}')
    if not isinstance(current, dict) or binding(current) != initial:
        return None
    return number
