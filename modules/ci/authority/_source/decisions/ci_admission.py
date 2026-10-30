#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Approve CI execution for live trusted identities; never approve PR reviews."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess

from decision_authority import AuthorityError, collection, eligible, github_api


def trusted(api, policy, user):
    if not isinstance(user, dict):
        return False
    bot = policy['bot']
    if user.get('type') == 'Bot':
        return (user.get('login') == bot['login'] and type(user.get('id')) is int
                and user['id'] == bot['id'])
    return eligible(api, policy['repository'], user)


def dependabot(policy, user):
    bot = policy['dependabot']
    return (isinstance(user, dict) and user.get('type') == 'Bot'
            and user.get('login') == bot['login'] and type(user.get('id')) is int
            and user['id'] == bot['id'])


def workflow_shape(text):
    # Permit only SHA updates on existing external action coordinates. Everything
    # else (triggers, guards, permissions, secrets, commands, local actions) must
    # match the protected controller's workflow byte for byte. Never parse or
    # execute candidate YAML. Anchor each replacement to a complete uses line.
    return re.sub(r'(?m)^( +(?:- )?uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@)'
                  r'[0-9a-f]{40}(?: +#[^\r\n]*)?$', r'\1<PIN>', text)


def safe_dependabot_workflow(api, policy, pull, run, templates):
    repository = {'id': policy['repositoryId'], 'full_name': policy['repository']}
    sources = (pull['head'].get('repo'), run.get('head_repository'))
    if (templates is None or run['path'] not in templates
            or any((source or {}).get('id') != repository['id']
                   or (source or {}).get('full_name') != repository['full_name']
                   for source in sources)):
        return False
    if not same_workflow(api, policy, run['path'], run['head_sha'], templates):
        return False
    base = pull.get('base', {}).get('sha')
    if not current_protected_base(api, policy, pull):
        return False
    # The comparison is immutable, unlike the moving PR-files endpoint. GitHub
    # caps comparison file inventories at 300; reaching that cap fails closed.
    comparison = api(f'repos/{policy["repository"]}/compare/{base}...{run["head_sha"]}?per_page=1')
    files = comparison.get('files')
    # pull_request executes a synthetic merge tree. When current protected main
    # is an ancestor of the head, that merge has exactly the audited head tree.
    # A diverged base can contribute executable files absent from the PR diff;
    # reject it rather than treating the head-only inventory as merge evidence.
    if (comparison.get('base_commit', {}).get('sha') != base
            or (comparison.get('merge_base_commit') or {}).get('sha') != base
            or comparison.get('status') not in ('ahead', 'identical')
            or type(comparison.get('behind_by')) is not int or comparison['behind_by'] != 0
            or not isinstance(files, list) or len(files) >= 300):
        return False
    names = set()
    for item in files:
        if not isinstance(item, dict) or item.get('status') != 'modified':
            return False
        path = item.get('filename')
        if not isinstance(path, str) or path in names:
            return False
        names.add(path)
        if path in policy['dependencyFiles']:
            continue
        if path not in templates or not same_workflow(api, policy, path, run['head_sha'], templates):
            return False
    return True


def current_protected_base(api, policy, pull):
    base = pull.get('base', {}).get('sha')
    if not isinstance(base, str) or not re.fullmatch(r'[0-9a-f]{40}', base):
        return False
    branch = api(f'repos/{policy["repository"]}/branches/main')
    return (branch.get('protected') is True
            and (branch.get('commit') or {}).get('sha') == base)


def same_workflow(api, policy, path, head, templates):
    response = api(f'repos/{policy["repository"]}/contents/{path}?ref={head}')
    if (response.get('type') != 'file' or response.get('encoding') != 'base64'
            or response.get('path') != path or not isinstance(response.get('content'), str)
            or type(response.get('size')) is not int
            or not 0 < response['size'] <= 128 * 1024):
        return False
    try:
        raw = base64.b64decode(''.join(response['content'].split()), validate=True)
        candidate = raw.decode('utf-8')
    except (KeyError, ValueError, UnicodeError):
        return False
    return (len(raw) == response['size']
            and workflow_shape(candidate) == workflow_shape(templates[path]))


def load_templates(root):
    root = Path(root)
    paths = list((root / '.github/workflows').glob('*.yml'))
    paths += list((root / '.github/workflows').glob('*.yaml'))
    for pattern in ('action.yml', 'action.yaml'):
        paths += list((root / '.github/actions').rglob(pattern))
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise AuthorityError('Invalid protected workflow template')
    return {str(path.relative_to(root)): path.read_text() for path in paths}


def run_binding(run):
    return {key: run.get(key) for key in (
        'id', 'run_attempt', 'event', 'head_sha', 'head_branch', 'head_repository',
        'repository', 'workflow_id', 'path', 'actor', 'triggering_actor')}


def valid_run(run, policy, run_id):
    return (run.get('id') == run_id and run.get('event') == 'pull_request'
            and run.get('conclusion') == 'action_required'
            and run.get('repository', {}).get('id') == policy['repositoryId']
            and run.get('repository', {}).get('full_name') == policy['repository']
            and run.get('path') in policy['workflows']
            and isinstance(run.get('head_sha'), str)
            and re.fullmatch(r'[0-9a-f]{40}', run['head_sha'])
            and type(run.get('workflow_id')) is int
            and type(run.get('run_attempt')) is int)


def pull_binding(pull):
    return {key: pull.get(key) for key in ('number', 'state', 'user', 'head', 'base')}


def matches(pull, run, policy):
    head, base = pull.get('head', {}), pull.get('base', {})
    return (pull.get('state') == 'open' and type(pull.get('number')) is int
            and base.get('ref') == 'main'
            and (base.get('repo') or {}).get('id') == policy['repositoryId']
            and head.get('sha') == run['head_sha'] and head.get('ref') == run['head_branch']
            and type((head.get('repo') or {}).get('id')) is int
            and (head.get('repo') or {}).get('id') == (run.get('head_repository') or {}).get('id'))


def approve_run(api, post, policy, run_id, templates=None):
    """Read twice around identity checks; no stale successful authorization reuse."""
    if type(run_id) is not int or run_id < 1:
        raise AuthorityError('Invalid CI run ID')
    prefix = 'repos/' + policy['repository']
    endpoint = f'{prefix}/actions/runs/{run_id}'
    run = api(endpoint)
    if not valid_run(run, policy, run_id):
        return 'not-pending-ci'
    workflow = api(f'{prefix}/actions/workflows/{run["workflow_id"]}')
    if workflow.get('path') != run['path'] or workflow.get('state') != 'active':
        return 'workflow-mismatch'
    # Fork workflow events can omit pull_requests. Resolve the immutable commit
    # through GitHub, then authenticate each candidate with a fresh PR read.
    candidates = collection(api, f'{prefix}/commits/{run["head_sha"]}/pulls')
    for candidate in candidates:
        number = candidate.get('number')
        if type(number) is not int or number < 1:
            raise AuthorityError('Invalid associated PR number')
        pull_endpoint = f'{prefix}/pulls/{number}'
        pull = api(pull_endpoint)
        if not matches(pull, run, policy):
            continue
        # A trusted PR author is not a blanket grant to an unrelated pusher or
        # rerun actor. Draft state is deliberately irrelevant to CI admission.
        users = [pull.get('user'), run.get('actor'), run.get('triggering_actor')]
        dependency_pr = dependabot(policy, pull.get('user'))

        def allowed(user):
            return trusted(api, policy, user) or (dependency_pr and dependabot(policy, user))

        if not all(allowed(user) for user in users):
            continue
        if dependency_pr and not safe_dependabot_workflow(api, policy, pull, run, templates):
            return 'unsafe-dependency-workflow'
        if not all(allowed(user) for user in users):
            return 'identity-revoked'
        current_pull = api(pull_endpoint)
        current_run = api(endpoint)
        if (pull_binding(current_pull) != pull_binding(pull)
                or not matches(current_pull, current_run, policy)
                or run_binding(current_run) != run_binding(run)
                or not valid_run(current_run, policy, run_id)):
            return 'binding-changed'
        if dependency_pr and not current_protected_base(api, policy, current_pull):
            return 'base-changed'
        # Approval endpoint only. No reviews, dispatch, branch writes or queue.
        # Never retry an ambiguous mutation: the next invocation reads anew.
        post(endpoint + '/approve')
        return 'approved'
    return 'no-trusted-current-pr'


def pending_runs(api, policy):
    endpoint = 'repos/' + policy['repository'] + '/actions/runs?event=pull_request&status=action_required'
    result = []
    for page in range(1, 11):
        response = api(endpoint + f'&per_page=100&page={page}')
        runs = response.get('workflow_runs')
        if not isinstance(runs, list) or len(runs) > 100:
            raise AuthorityError('Invalid bounded pending CI inventory')
        result.extend(run['id'] for run in runs)
        if len(runs) < 100:
            return result
    raise AuthorityError('Pending CI inventory exceeds bounded pagination')


def post_approval(endpoint):
    subprocess.run(['gh', 'api', '--method', 'POST', endpoint], check=True,
                   stdout=subprocess.DEVNULL, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--source-root', required=True)
    args = parser.parse_args()
    policy = json.loads(Path(args.policy).read_text())
    if (policy.get('schema') != 1 or policy['repository'] != os.environ.get('GITHUB_REPOSITORY')
            or not re.fullmatch(r'closure-labs/(maestro|xo-nixpkg)', policy['repository'])):
        raise AuthorityError('CI admission policy repository mismatch')
    templates = load_templates(args.source_root)
    event_run = os.environ.get('CI_ADMISSION_RUN_ID', '')
    run_ids = [int(event_run)] if event_run else pending_runs(github_api, policy)
    for run_id in run_ids:
        print(json.dumps({'runId': run_id, 'result': approve_run(
            github_api, post_approval, policy, run_id, templates)}, sort_keys=True))


if __name__ == '__main__':
    main()
