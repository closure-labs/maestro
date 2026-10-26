#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retain exact derivations from both native JSON formats during assembly."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DRV = '/nix/store/' + 'a' * 32 + '-fixture.drv'
OUTPUT = '/nix/store/' + 'b' * 32 + '-fixture'


class QualificationDiagnostics(unittest.TestCase):
    def assemble(self, document, valid=True):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'bin'
            binary.mkdir()
            media = root / 'reused-media'
            (media / 'result-installer/iso').mkdir(parents=True)
            (media / 'result-installer/iso/maestro-installer.iso').write_bytes(b'previously verified media')
            (media / 'maestro-qualification-state.json').write_text(json.dumps({
                'artifact_source_commit': 'a' * 40, 'media_input': 'b' * 64}))
            (root / 'input.json').write_text(json.dumps(document))
            (root / 'modules/ci/graph/_lib').mkdir(parents=True)
            (root / 'modules/ci/graph/_lib/plans.json').write_bytes((ROOT / 'modules/ci/graph/_lib/plans.json').read_bytes())
            for name, body in {
                'maestro-ci-security-inventory-preflight': 'exit 0',
                'maestro-ci-qualification-cache': 'exit 0',
                'maestro-ci-verify-inventory': 'exit 0',
                'nix': '''case "$1 $2" in
  'eval --accept-flake-config') echo /nix/store/fixture ;;
  'derivation show') cat "$DIAGNOSTIC_INPUT" ;;
  *) exit 0 ;;
esac''',
                'flake-plan-runner': 'touch "$DIAGNOSTIC_PLAN_CALLED"; exit 24',
            }.items():
                path = binary / name
                path.write_text('#!' + shutil.which('bash') + '\nset -euo pipefail\n' + body + '\n')
                path.chmod(0o755)
            environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ['PATH'],
                               MAESTRO_SYSTEM_ROOT=str(root), RUNNER_TEMP=str(root),
                               MAESTRO_SPDX_SCHEMA='unused-before-build', QUALIFICATION_MODE='refresh-evidence',
                               GH_TOKEN='fixture-never-network', EXPECTED_MEDIA_INPUT='b' * 64,
                               DIAGNOSTIC_INPUT=str(root / 'input.json'),
                               DIAGNOSTIC_PLAN_CALLED=str(root / 'plan-called'))
            # Run in a synthetic source root; every Nix/verification executable is
            # a stub. Only the declared plan data comes from the real source.
            result = subprocess.run(['bash', str(ROOT / 'modules/ci/authority/_source/qualification-assets.sh')],
                                    cwd=root, env=environment,
                                    capture_output=True, timeout=15)
            diagnostics = root / 'maestro-qualification-diagnostics'
            self.assertTrue(json.loads((diagnostics / 'reuse.json').read_text())['mediaReuseVerified'])
            self.assertEqual((root / 'plan-called').exists(), valid)
            if valid:
                self.assertEqual(result.returncode, 24, result.stderr)
                self.assertEqual(json.loads((diagnostics / 'derivations.json').read_text()),
                                 {DRV: {'outputs': {'out': {'path': OUTPUT}}}})
            else:
                self.assertNotEqual(result.returncode, 0)
            stages = [json.loads(line) for line in (diagnostics / 'stages.jsonl').read_text().splitlines()]
            self.assertEqual(stages[-1]['stage'], 'evidence-realization')
            self.assertEqual(stages[-1]['status'], 'failure')

    def test_legacy_derivation_map(self):
        self.assemble({DRV: {'outputs': {'out': {'path': OUTPUT}}, 'env': {'discard': 'unused'}}})

    def test_version_four_envelope(self):
        self.assemble({'version': 4, 'derivations': {
            DRV: {'version': 4, 'outputs': {'out': {'path': OUTPUT}}}}})

    def test_unsupported_envelope_blocks_before_realization(self):
        self.assemble({'version': 99, 'derivations': {}}, valid=False)


if __name__ == '__main__':
    unittest.main()
