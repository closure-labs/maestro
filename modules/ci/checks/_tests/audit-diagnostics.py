#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The existing audit retains timing/failure evidence without a second run."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]


class AuditDiagnostics(unittest.TestCase):
    def run_audit(self, failure):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'bin'
            binary.mkdir()
            for name, body in {
                'maestro-ci-security-inventory-preflight': 'exit "${FAIL_PREFLIGHT:-0}"',
                'nix': 'exit "${FAIL_EVALUATION:-0}"',
                'flake-plan-runner': '''
printf 'run\\n' >> "$CALLS"
while (($#)); do
  case "$1" in
    --manifest|--timings) printf '{"native":true}\\n' > "$2"; shift 2 ;;
    *) shift ;;
  esac
done
exit "${FAIL_TARGETS:-0}"
''',
            }.items():
                path = binary / name
                path.write_text('#!' + shutil.which('bash') + '\nset -euo pipefail\n' + body + '\n')
                path.chmod(0o755)
            evidence = root / 'evidence'
            calls = root / 'calls'
            environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ['PATH'],
                               MAESTRO_SYSTEM_ROOT=str(root), CALLS=str(calls),
                               MAESTRO_CI_AUDIT_MANIFEST=str(evidence / 'audit.json'),
                               MAESTRO_CI_AUDIT_TIMINGS=str(evidence / 'timings.json'),
                               FAIL_PREFLIGHT='7' if failure == 'inventory-preflight' else '0',
                               FAIL_EVALUATION='8' if failure == 'flake-evaluation' else '0',
                               FAIL_TARGETS='9' if failure == 'validation-targets' else '0')
            result = subprocess.run(['bash', str(ROOT / 'modules/ci/checks/_source/repository-audit.sh')],
                                    cwd=root, env=environment, capture_output=True, timeout=15)
            summary = json.loads((evidence / 'timings.summary.json').read_text())
            self.assertEqual(summary['exitCode'], result.returncode)
            self.assertGreaterEqual(summary['elapsedSeconds'], 0)
            if failure:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(summary['phase'], failure)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
            expected_runs = int(failure not in ('inventory-preflight', 'flake-evaluation'))
            self.assertEqual(calls.read_text().count('run\n') if calls.exists() else 0, expected_runs)
            self.assertEqual((evidence / 'audit.json').exists(), bool(expected_runs))
            self.assertEqual((evidence / 'timings.json').exists(), bool(expected_runs))

    def test_success(self):
        self.run_audit(None)

    def test_failures_retain_the_original_phase_and_exit(self):
        for phase in ('inventory-preflight', 'flake-evaluation', 'validation-targets'):
            with self.subTest(phase=phase):
                self.run_audit(phase)


if __name__ == '__main__':
    unittest.main()
