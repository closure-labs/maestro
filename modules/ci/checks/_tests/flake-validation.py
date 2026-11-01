#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the real validation shell with a fake Nix; no evaluation or builds."""
import json
import os
import re
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
CACHE_SOURCE = (ROOT / 'modules/flake/caches.nix').read_text()


def cache_values(field):
    body = re.search(re.escape(field) + r' = \[([^\]]+)\]', CACHE_SOURCE, re.S).group(1)
    return re.findall(r'"([^"]+)"', body)


CACHE_URLS = cache_values('extra-substituters')
CACHE_KEYS = cache_values('extra-trusted-public-keys')
BASE_CONFIG = 'substituters = https://cache.nixos.org/\nmax-jobs = 1'
EXPECTED_CONFIG = (BASE_CONFIG + '\nextra-substituters = ' + ' '.join(CACHE_URLS)
                   + '\nextra-trusted-public-keys = ' + ' '.join(CACHE_KEYS))


class FlakeValidation(unittest.TestCase):
    def run_shell(self, fail_at=0, missing_cache=False):
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
    stream.write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(), 'nixConfig': os.environ['NIX_CONFIG']}) + '\\n')
if count + 1 == int(os.environ['FAKE_NIX_FAIL_AT']):
    sys.exit(17)
''')
            fake.chmod(0o700)
            env = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ['PATH'],
                       FAKE_NIX_CALLS=str(calls), FAKE_NIX_FAIL_AT=str(fail_at), MAESTRO_SYSTEM_ROOT=str(ROOT),
                       NIX_CONFIG=BASE_CONFIG, MAESTRO_FLAKE_CACHE_URLS=' '.join(CACHE_URLS),
                       MAESTRO_FLAKE_CACHE_KEYS=' '.join(CACHE_KEYS))
            if missing_cache:
                del env['MAESTRO_FLAKE_CACHE_KEYS']
            result = subprocess.run([shutil.which('bash'), str(SOURCE)], cwd=directory, env=env,
                                    capture_output=True, text=True, timeout=10)
            rows = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
            self.assertTrue(all(row['nixConfig'] == EXPECTED_CONFIG for row in rows))
            self.assertTrue(all(row['cwd'] == str(ROOT) for row in rows))
            return result, [row['argv'] for row in rows]

    def test_real_shell_realizes_all_checks_and_essential_products_once(self):
        result, calls = self.run_shell()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [['flake', 'check', '--no-write-lock-file', '--print-build-logs'],
                                ['build', '--no-write-lock-file', '--no-link', '--print-build-logs', *PRODUCTS]])
        self.assertEqual(result.stdout, '')
        self.assertIn('Realize all ordinary flake checks', result.stderr)
        self.assertIn('Build the appliance', result.stderr)
        self.assertIn('Ordinary flake validation completed', result.stderr)
        plan = json.loads((ROOT / 'modules/ci/graph/_lib/plans.json').read_text())
        targets = plan['validation']['targets']
        self.assertEqual(len(targets), 20)
        self.assertTrue(all(t['attribute'].startswith('checks.x86_64-linux.') for t in targets))

    def test_each_failure_stops_without_fallback_or_further_builds(self):
        for phase in (1, 2):
            with self.subTest(phase=phase):
                result, calls = self.run_shell(phase)
                self.assertEqual(result.returncode, 17)
                self.assertEqual(len(calls), phase)

    def test_missing_cache_configuration_fails_before_any_nix_command(self):
        result, calls = self.run_shell(missing_cache=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_cache_lists_are_inherited_from_existing_declarations_without_expansion(self):
        generated = (ROOT / 'flake.nix').read_text()
        for field, expected in (('extra-substituters', CACHE_URLS), ('extra-trusted-public-keys', CACHE_KEYS)):
            body = re.search(re.escape(field) + r' = \[([^\]]+)\]', generated, re.S).group(1)
            self.assertEqual(re.findall(r'"([^"]+)"', body), expected)
        owner = (ROOT / 'modules/ci/checks/commands.nix').read_text()
        self.assertIn('cacheConfig = config.flake-file.nixConfig;', owner)
        packaged = (ROOT / 'modules/ci/checks/_lib/commands.nix').read_text()
        self.assertIn('pkgs.lib.escapeShellArg (pkgs.lib.concatStringsSep " " cacheConfig.extra-substituters)', packaged)
        self.assertIn('pkgs.lib.escapeShellArg (pkgs.lib.concatStringsSep " " cacheConfig.extra-trusted-public-keys)', packaged)
        self.assertNotIn('--accept-flake-config', SOURCE.read_text())
        self.assertNotIn('TOKEN', SOURCE.read_text())

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
