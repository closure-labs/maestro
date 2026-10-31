# SPDX-License-Identifier: Apache-2.0
"""Exact-attempt scheduling proof: no authority or evidence shortcut."""
import copy
import json
import re
from pathlib import Path
import sys
import unittest

SOURCE = Path(__file__).resolve().parents[2] / '_source' / 'decisions'
sys.path.insert(0, str(SOURCE))
import continuation_wakeup as wakeup

SHA = 'a' * 40
NEW = 'b' * 40
PREFIX = 'repos/closure-labs/maestro'
ENDPOINT = PREFIX + '/actions/runs/12/attempts/2'


class Proof(unittest.TestCase):
    def setUp(self):
        repo = {'id': wakeup.REPOSITORY_ID, 'full_name': wakeup.REPOSITORY}
        self.run = dict(id=12, run_attempt=2, workflow_id=34, path=wakeup.WORKFLOW,
                        repository=repo, head_repository=repo, head_sha=SHA,
                        head_branch='main', event='workflow_run', status='completed',
                        conclusion='success', referenced_workflows=[{
                            'path': f'{wakeup.REPOSITORY}/.github/workflows/release.yml@{SHA}',
                            'sha': SHA, 'ref': 'refs/heads/main'}])
        self.event = {'workflow_run': copy.deepcopy(self.run)}
        self.calls = []
        self.final_read = None
        self.workflow = dict(id=34, path=wakeup.WORKFLOW, state='active')
        self.branch = dict(protected=True, commit={'sha': NEW})
        self.compare = dict(merge_base_commit={'sha': SHA}, status='ahead')
        self.jobs([wakeup.RESOLVER, 'finalize'], ['success', 'skipped'])

    def jobs(self, names, conclusions):
        self.inventory = {'total_count': len(names), 'jobs': [
            dict(id=i+1, name=name, conclusion=conclusion, run_id=12, run_attempt=2,
                 head_sha=SHA, head_branch='main', status='completed')
            for i, (name, conclusion) in enumerate(zip(names, conclusions))]}

    def real(self):
        self.jobs([wakeup.RESOLVER, wakeup.CONTEXT, wakeup.SECURITY, wakeup.FINAL], ['success']*4)

    def api(self, endpoint):
        self.calls.append(endpoint)
        if endpoint == ENDPOINT:
            if self.calls.count(endpoint) > 1 and self.final_read is not None:
                return copy.deepcopy(self.final_read)
            return copy.deepcopy(self.run)
        return copy.deepcopy({PREFIX + '/actions/workflows/34': self.workflow,
                              PREFIX + '/branches/main': self.branch,
                              PREFIX + f'/compare/{SHA}...{NEW}?per_page=1': self.compare,
                              ENDPOINT + '/jobs?per_page=100': self.inventory}[endpoint])

    def check(self):
        return wakeup.meaningful(self.api, self.event)

    def test_exact_noop_uses_six_gets_and_no_mutations(self):
        self.assertFalse(self.check())
        self.assertEqual(len(self.calls), 6)
        self.assertFalse(any('/artifacts' in call for call in self.calls))

    def test_real_finalization(self):
        self.real()
        self.assertTrue(self.check())
        self.assertEqual(len(self.calls), 6)

    def test_manual_release_continuation(self):
        self.real()
        self.run['event'] = 'workflow_dispatch'
        self.assertTrue(self.check())

    def test_delayed_event_on_ancestor_preserves_real_work(self):
        self.real()
        self.assertNotEqual(self.run['head_sha'], self.branch['commit']['sha'])
        self.assertTrue(self.check())

    def test_rerun_uses_event_attempt_never_latest(self):
        self.real()
        self.assertTrue(self.check())
        self.assertTrue(all('/actions/runs/12/attempts/2' in c for c in self.calls if '/actions/runs/' in c))

    def test_wrong_attempt_or_run_job_cannot_prove_noop(self):
        for key, value in [('run_attempt', 1), ('run_id', 99), ('head_sha', NEW), ('head_branch', 'topic')]:
            with self.subTest(key=key):
                old = self.inventory['jobs'][1][key]
                self.inventory['jobs'][1][key] = value
                with self.assertRaises(ValueError): self.check()
                self.inventory['jobs'][1][key] = old

    def test_missing_or_ambiguous_jobs_block(self):
        for change in ('missing', 'duplicate', 'capped', 'unknown'):
            with self.subTest(change=change):
                original = copy.deepcopy(self.inventory)
                if change == 'missing': self.inventory['jobs'].pop()
                if change == 'duplicate': self.inventory['jobs'][1] = self.inventory['jobs'][0]
                if change == 'capped': self.inventory['total_count'] = 101
                if change == 'unknown': self.inventory['jobs'][1]['name'] = 'arbitrary successful output'
                with self.assertRaises(ValueError): self.check()
                self.inventory = original

    def test_spoofed_repository_workflow_or_source_blocks(self):
        for field, value in [('path', '.github/workflows/untrusted.yml'), ('repository', {}),
                             ('head_repository', {'id': 9}), ('head_branch', 'topic'),
                             ('referenced_workflows', []), ('conclusion', 'failure'),
                             ('event', 'pull_request'), ('run_attempt', 1)]:
            with self.subTest(field=field):
                original = self.run[field]
                self.run[field] = value
                with self.assertRaises(ValueError): self.check()
                self.run[field] = original

    def test_unprotected_or_diverged_source_blocks(self):
        self.branch['protected'] = False
        with self.assertRaises(ValueError): self.check()
        self.branch['protected'] = True
        self.compare['merge_base_commit']['sha'] = NEW
        with self.assertRaises(ValueError): self.check()

    def test_revoked_workflow_and_attempt_race_block(self):
        self.workflow['state'] = 'disabled_manually'
        with self.assertRaises(ValueError): self.check()
        self.workflow['state'] = 'active'
        self.final_read = dict(self.run, conclusion='failure')
        with self.assertRaises(ValueError): self.check()

    def test_real_requires_successful_context_security_and_product(self):
        for name in (wakeup.CONTEXT, wakeup.SECURITY, wakeup.FINAL):
            self.real()
            next(j for j in self.inventory['jobs'] if j['name'] == name)['conclusion'] = 'skipped'
            with self.assertRaises(ValueError): self.check()

    def test_missing_identity_and_boolean_attempt_block(self):
        for hint in ({}, {'id':12}, {'id':12, 'run_attempt':True}):
            self.event['workflow_run'] = hint
            with self.assertRaises(ValueError): self.check()

    def test_transport_failure_is_not_a_noop(self):
        def unavailable(_): raise OSError('unavailable')
        with self.assertRaises(OSError): wakeup.meaningful(unavailable, self.event)


class Workflow(unittest.TestCase):
    def condition(self, job, event, continuation='skipped', meaningful=''):
        text = (Path(__file__).resolve().parents[5] / '.github/workflows/decisions.yml').read_text()
        section = text.split('  ' + job + ':\n', 1)[1]
        expression = next(line.strip()[4:] for line in section.splitlines() if line.startswith('    if:'))
        expression = expression.removeprefix('${{ ').removesuffix(' }}')
        values = {
            'github.event_name': event, 'github.repository': wakeup.REPOSITORY,
            'github.ref': 'refs/heads/main', 'github.event.workflow_run.name': 'CI',
            'github.event.workflow_run.path': '.github/workflows/ci.yml',
            'github.event.workflow_run.conclusion': 'success',
            'github.event.workflow_run.head_branch': 'main',
            'github.event.workflow_run.repository.full_name': wakeup.REPOSITORY,
            'github.event.workflow_run.event': 'push',
            'needs.continuation.result': continuation,
            'needs.continuation.outputs.meaningful': meaningful}
        expression = re.sub(r'(?:github|needs)\.[A-Za-z_.]+', lambda m: repr(values[m.group()]), expression)
        expression = expression.replace('!cancelled()', 'True').replace('&&', ' and ').replace('||', ' or ')
        return eval(expression, {'__builtins__': {}, 'fromJSON': json.loads, 'contains': lambda xs,x: x in xs})

    def test_manual_schedule_push_and_other_native_completions_bypass_gate(self):
        for job in ('health', 'reconcile'):
            for event in ('workflow_dispatch', 'schedule', 'push', 'workflow_run'):
                with self.subTest(job=job, event=event):
                    self.assertTrue(self.condition(job, event))

    def test_noop_or_failed_proof_blocks_both_consumers(self):
        for job in ('health', 'reconcile'):
            self.assertFalse(self.condition(job, 'workflow_run', 'success', 'false'))
            self.assertFalse(self.condition(job, 'workflow_run', 'failure', 'true'))
            self.assertFalse(self.condition(job, 'workflow_run', 'success', ''))
            self.assertTrue(self.condition(job, 'workflow_run', 'success', 'true'))

    def test_only_continuations_are_gated_and_both_consumers_wait(self):
        root = Path(__file__).resolve().parents[5]
        text = (root / '.github/workflows/decisions.yml').read_text()
        self.assertIn("github.event_name == 'workflow_run' && (github.event.workflow_run.path", text)
        self.assertEqual(text.count('needs: continuation'), 2)
        self.assertEqual(text.count("needs.continuation.result == 'skipped'"), 2)
        self.assertEqual(text.count("needs.continuation.outputs.meaningful == 'true'"), 2)
        self.assertIn('workflows: [CI, Security maintenance, Release Maestro, Continue Maestro release, Verify maintainer decision authority]', text)
        self.assertIn('workflow_dispatch:', text)
        self.assertIn("- cron: '37 * * * *'", text)
        self.assertNotIn('CANDIDATE_RUN_ATTEMPT', text)


if __name__ == '__main__': unittest.main()
