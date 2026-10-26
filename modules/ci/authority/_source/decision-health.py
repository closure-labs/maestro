#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Maintain one operational health issue; elapsed time never grants authority."""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, os.environ.get('MAESTRO_DECISION_CORE', str(Path(__file__).with_name('decisions'))))
import common
from decision_authority import github_api, collection
from security_decisions import load_json

TITLE = 'Automation health: security audit or human decision needs attention'
MARKER = '<!-- maestro-decision-health:v1 -->'


def problems(runs, pulls, bot, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    successful = [r for r in runs if r.get('status') == 'completed' and r.get('conclusion') == 'success'
                  and r.get('head_branch') == 'main' and r.get('path', '').split('@')[0] == '.github/workflows/security.yml'
                  and r.get('event') in ('schedule', 'workflow_dispatch')
                  and r.get('_nativeAudit', r.get('event') == 'schedule') is True]
    newest = max((common.timestamp(r['updated_at']) for r in successful), default=None)
    result = []
    if newest is None or now - newest > dt.timedelta(hours=36):
        result.append('No successful protected security audit has completed within 36 hours.')
    for pull in pulls:
        if (pull.get('state') == 'open' and pull.get('user', {}).get('login') == bot
                and pull.get('head', {}).get('ref', '').startswith('automation/decision-')
                and pull.get('base', {}).get('ref') == 'main'
                and now - common.timestamp(pull['created_at']) > dt.timedelta(hours=72)):
            common.require(type(pull.get('number')) is int and pull['number'] > 0, 'Invalid pending decision PR identity')
            result.append('Human decision PR #' + str(pull['number']) + ' has been pending for more than 72 hours.')
    return sorted(result)


def write_issue(repository, issues, findings, write=None):
    matches = [i for i in issues if i.get('title') == TITLE and MARKER in i.get('body', '') and not i.get('pull_request')]
    common.require(len(matches) <= 1, 'Multiple health issues require explicit reconciliation')
    body = MARKER + '\n\n' + '\n'.join('- ' + text for text in findings)
    body += '\n\nPublication remains subject to fresh native health and current human authority. These thresholds grant no acceptance or release permission.\n'
    if write is None:
        def write(endpoint, payload, method):
            return json.loads(common.command(['gh', 'api', '--method', method, endpoint, '--input', '-'], input=json.dumps(payload)))
    if not findings:
        if matches:
            write(f'repos/{repository}/issues/{matches[0]["number"]}', {'state': 'closed', 'state_reason': 'completed'}, 'PATCH')
        return 'healthy'
    if matches:
        if matches[0].get('body') != body:
            write(f'repos/{repository}/issues/{matches[0]["number"]}', {'body': body}, 'PATCH')
        return 'attention-required'
    write(f'repos/{repository}/issues', {'title': TITLE, 'body': body}, 'POST')
    return 'attention-required'


def main():
    root = Path(os.environ.get('MAESTRO_SYSTEM_ROOT', '.')).resolve()
    policy = load_json(Path(os.environ.get('MAESTRO_DECISION_POLICY', str(root / 'modules/ci/authority/_source/decision-policy.json'))))
    common.authority.validate_context(policy.get('repository'), policy.get('botLogin'))
    repository = policy['repository']
    # Health reporting remains usable while appId/enabled are frozen for setup.
    revision = common.main_revision(policy)
    checked = common.authority.document_at(github_api, repository, policy['policyPath'], revision)
    common.require(policy == checked, 'Health policy differs from current main')
    response = github_api(f'repos/{repository}/actions/workflows/security.yml/runs?branch=main&per_page=100')
    common.require(isinstance(response, dict) and isinstance(response.get('workflow_runs'), list), 'Invalid audit workflow inventory')
    for workflow in response['workflow_runs']:
        if workflow.get('event') == 'workflow_dispatch' and workflow.get('conclusion') == 'success':
            jobs = github_api(f'repos/{repository}/actions/runs/{workflow["id"]}/attempts/{workflow["run_attempt"]}/jobs?per_page=100')
            common.require(isinstance(jobs.get('jobs'), list) and jobs.get('total_count') == len(jobs['jobs']) <= 100,
                           'Complete native audit job inventory required')
            workflow['_nativeAudit'] = any(j.get('name') == 'Rescan latest trusted inventories'
                                           and j.get('conclusion') == 'success' for j in jobs['jobs'])
    pulls = collection(github_api, f'repos/{repository}/pulls?state=open&base=main')
    issues = collection(github_api, f'repos/{repository}/issues?state=open&creator={policy["botLogin"]}')
    findings = problems(response['workflow_runs'], pulls, policy['botLogin'])
    status = write_issue(repository, issues, findings)
    common.emit({'schema': 1, 'status': status, 'problems': findings})


if __name__ == '__main__':
    sys.exit(common.run(main))
