#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the real validation shell with a fake Nix; no evaluation or builds."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
SOURCE = ROOT / 'modules/ci/checks/_source/flake-validation.sh'
WORKFLOW = ROOT / '.github/workflows/flake-checks.yml'
PRODUCTS = ['.#nixosConfigurations.maestro.config.system.build.toplevel', '.#installer-iso',
            '.#xen-orchestra-ce', '.#maestro-menu', '.#maestroctl', '.#deploy-template']
CHECKS = ['.#checks.x86_64-linux.maestroctl', '.#checks.x86_64-linux.runtime-security',
          '.#checks.x86_64-linux.xo-storage-fixtures', '.#checks.x86_64-linux.xo-file-restore-fixtures']


class FlakeValidation(unittest.TestCase):
    def run_shell(self, fail_at=0):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            calls = directory / 'calls.jsonl'
            fake = directory / 'nix'
            fake.write_text('#!' + sys.executable + '\n' + '''
import json, os, sys
from pathlib import Path
p = Path(os.environ['FAKE_NIX_CALLS'])
count = len(p.read_text().splitlines()) if p.exists() else 0
with p.open('a') as stream:
    stream.write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd()}) + '\\n')
if count + 1 == int(os.environ['FAKE_NIX_FAIL_AT']):
    sys.exit(17)
''')
            fake.chmod(0o700)
            env = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ['PATH'],
                       FAKE_NIX_CALLS=str(calls), FAKE_NIX_FAIL_AT=str(fail_at), MAESTRO_SYSTEM_ROOT=str(ROOT))
            result = subprocess.run([shutil.which('bash'), str(SOURCE)], cwd=directory, env=env,
                                    capture_output=True, text=True, timeout=10)
            rows = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertTrue(all(row['cwd'] == str(ROOT) for row in rows))
            return result, [row['argv'] for row in rows]

    def test_real_shell_runs_only_pure_evaluation_and_explicit_builds(self):
        result, calls = self.run_shell()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [['flake', 'check', '--no-write-lock-file', '--no-build'],
                                ['build', '--no-write-lock-file', '--no-link', *PRODUCTS],
                                ['build', '--no-write-lock-file', '--no-link', *CHECKS]])

    def test_each_failure_stops_without_fallback_or_further_builds(self):
        for phase in (1, 2, 3):
            with self.subTest(phase=phase):
                result, calls = self.run_shell(phase)
                self.assertEqual(result.returncode, 17)
                self.assertEqual(len(calls), phase)

    def test_workflow_has_one_nonrequired_read_only_job_and_no_consumers(self):
        value = json.loads(subprocess.check_output(['yq', '-o=json', '.', str(WORKFLOW)], text=True))
        self.assertEqual(value['permissions'], {'contents': 'read'})
        self.assertEqual(set(value['on']), {'pull_request', 'merge_group', 'push', 'workflow_dispatch'})
        self.assertEqual(value['on']['push']['branches'], ['main'])
        self.assertEqual(value['on']['pull_request']['branches'], ['main'])
        self.assertEqual(set(value['jobs']), {'flake-checks'})
        job = value['jobs']['flake-checks']
        self.assertEqual(job['name'], 'Ordinary flake validation (non-required)')
        self.assertLessEqual(job['timeout-minutes'], 120)
        self.assertNotIn('permissions', job)
        self.assertNotIn('needs', job)
        self.assertNotIn('environment', job)
        steps = job['steps']
        self.assertEqual(len(steps), 3)
        self.assertFalse(steps[0]['with']['persist-credentials'])
        self.assertNotIn('ref', steps[0]['with'])  # Test the actual PR/queue tree.
        self.assertEqual(steps[1]['uses'], '$/.github/actions/setup-nix')
        self.assertTrue(steps[2]['run'].endswith('ci:flake:validate'))
        self.assertNotIn('secrets.', WORKFLOW.read_text())
        self.assertFalse(any('env' in step for step in steps))
        policy = json.loads((ROOT / 'modules/ci/authority/_source/github/main-ruleset.json').read_text())
        required = [check['context'] for rule in policy['rules'] if rule['type'] == 'required_status_checks'
                    for check in rule['parameters']['required_status_checks']]
        self.assertNotIn(job['name'], required)
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            workflow = json.loads(subprocess.check_output(['yq', '-o=json', '.', str(path)], text=True))
            triggers = workflow.get('on') or {}
            consumers = (triggers.get('workflow_run') or {}).get('workflows', [])
            self.assertNotIn(value['name'], consumers, str(path))

    def test_task_is_native_and_trial_has_an_explicit_end(self):
        tasks = (ROOT / 'modules/ci/checks/_lib/tasks.nix').read_text()
        self.assertIn('"ci:flake:validate".exec = runFlakePackage "maestro-ci-flake-validation" "";', tasks)
        commands = (ROOT / 'modules/ci/checks/_lib/commands.nix').read_text()
        self.assertIn('runtimeInputs = [ciNix];', commands)
        note = (ROOT / 'docs/flake-validation-migration.md').read_text()
        self.assertIn('one agreed PR/merge-group validation cycle', note)
        self.assertIn('Delete `flake-checks.yml` in that same cutover', note)


if __name__ == '__main__':
    unittest.main()
