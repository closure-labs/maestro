#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep the worst-case queue DAG inside its response budget, without skipping work."""
import copy
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[4]


def workflow(name):
    return json.loads(subprocess.check_output(['yq', '-o=json', '.', str(ROOT / '.github/workflows' / name)], text=True))


def minutes(job):
    value = job['timeout-minutes']
    if isinstance(value, int):
        return value
    match = re.fullmatch(r"\$\{\{ github.event_name == 'merge_group' && (\d+) \|\| (\d+) \}\}", value)
    if not match:
        raise ValueError('Unrecognized queue timeout expression')
    return int(match[1])


def longest_path(jobs, secret_minutes):
    finished = {}
    visiting = set()
    def finish(name):
        if name in finished:
            return finished[name]
        if name in visiting:
            raise ValueError('Cyclic queue dependency')
        visiting.add(name)
        job = jobs[name]
        dependencies = job.get('needs', [])
        if isinstance(dependencies, str):
            dependencies = [dependencies]
        before = max((finish(parent) for parent in dependencies), default=0)
        duration = secret_minutes if name == 'incoming_secret_scan' else minutes(job)
        # Signing is protected-main only, never a merge-group job. Keep its
        # dependencies in the model so that changing its graph is visible.
        if name == 'signing':
            if "github.ref == 'refs/heads/main'" not in job['if']:
                raise ValueError('Signing queue exclusion changed')
            duration = 0
        finished[name] = before + duration
        visiting.remove(name)
        return finished[name]
    return finish('verdict')


class QueueTimeouts(unittest.TestCase):
    def setUp(self):
        self.jobs = workflow('ci.yml')['jobs']
        self.secret = max(minutes(j) for j in workflow('repository-secret-scan.yml')['jobs'].values())
        policy = json.loads((ROOT / 'modules/ci/authority/_source/github/main-ruleset.json').read_text())
        self.limit = next(r for r in policy['rules'] if r['type'] == 'merge_queue')['parameters']['check_response_timeout_minutes']

    def test_bounded_queue_path_has_scheduling_margin(self):
        self.assertGreaterEqual(self.limit, 1)
        self.assertLessEqual(self.limit, 360)  # GitHub's documented API bound
        self.assertEqual(longest_path(self.jobs, self.secret), 315)
        self.assertGreaterEqual(self.limit - longest_path(self.jobs, self.secret), 45)
        # Other required workflows run in parallel, not after the CI graph.
        for filename in ('codeql.yml', 'decision-authority.yml'):
            self.assertLessEqual(sum(minutes(j) for j in workflow(filename)['jobs'].values()), self.limit - 45)

    def test_all_executable_jobs_are_explicitly_bounded(self):
        for name, job in self.jobs.items():
            if name != 'incoming_secret_scan':
                self.assertGreater(minutes(job), 0)
                self.assertLessEqual(minutes(job), self.limit)

    def test_nonqueue_expensive_job_limits_are_not_reduced(self):
        for name in ('appliance', 'installer', 'qualification', 'boot'):
            self.assertTrue(self.jobs[name]['timeout-minutes'].endswith('|| 240 }}'))

    def test_model_detects_future_budget_growth(self):
        changed = copy.deepcopy(self.jobs)
        changed['appliance']['timeout-minutes'] = 240
        self.assertGreater(longest_path(changed, self.secret), self.limit)

    def test_unknown_expression_or_cycle_rejects(self):
        with self.assertRaises(ValueError):
            minutes({'timeout-minutes': '${{ inputs.timeout }}'})
        changed = copy.deepcopy(self.jobs)
        changed['route']['needs'] = 'verdict'
        with self.assertRaises(ValueError):
            longest_path(changed, self.secret)


if __name__ == '__main__':
    unittest.main()
