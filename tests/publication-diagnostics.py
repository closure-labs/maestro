#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Same-execution evidence, bounded summaries and original shell failure status."""
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'nix/automation/decisions'))
import common
import diagnostics
import destinations


class Diagnostics(unittest.TestCase):
    def test_controllers_retain_execution_bound_diagnostics_on_success_and_failure(self):
        for name in ('publication.yml', 'release-publication.yml'):
            workflow = json.loads(subprocess.check_output(
                ['yq', '-o=json', '.', str(ROOT / '.github/workflows' / name)], text=True))
            job = workflow['jobs']['publish']
            self.assertEqual(job['env']['MAESTRO_CI_DIAGNOSTICS'], 'true')
            finalizer = next(step for step in job['steps'] if step.get('run', '').endswith(' release:diagnostics'))
            self.assertEqual(finalizer['if'], 'always()')
            self.assertNotIn('env', finalizer)
            artifact = next(step for step in job['steps'] if step.get('name') == 'Retain complete publication diagnostics')
            self.assertEqual(artifact['if'], 'always()')
            self.assertEqual(artifact['with']['name'], 'maestro-publication-diagnostics-${{ github.job }}-${{ github.run_id }}-${{ github.run_attempt }}')
            self.assertEqual(artifact['with']['path'], '${{ runner.temp }}/publication-diagnostics/')
            self.assertLess(job['steps'].index(finalizer), job['steps'].index(artifact))

    def test_bounded_allowlist_retains_complete_result_and_manifest_hashes(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp,
            'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'
        }), patch.dict(diagnostics.COUNTERS, {}, clear=True):
            result = {'status': 'verified', 'expected': {str(i): i for i in range(20000)},
                      'productHash': 'b' * 64, 'untrustedField': 'private detail' * 10000}
            diagnostics.count('gateInvocations')
            value = diagnostics.record(result, 'publication')
            diagnostics.record(result, 'gate', logged=False)
            summary = json.loads(value)
            self.assertLessEqual(len(value.encode()), 4096)
            self.assertEqual(summary['logBytes'], len(value.encode()))
            self.assertNotIn('private detail', value)
            self.assertEqual(summary['rootCount'], 20000)
            self.assertIsNone(summary['httpAttempts'])
            diagnostics.manifest()
            root = Path(temp) / 'publication-diagnostics'
            manifest = json.loads((root / 'manifest.json').read_text())
            self.assertEqual((manifest['source'], manifest['run'], manifest['attempt']), ('a' * 40, '123', '2'))
            self.assertEqual(manifest['measurements']['gateInvocations'], 1)
            self.assertEqual(manifest['measurements']['logBytes'], len(value.encode()))
            for name, record in manifest['files'].items():
                raw = (root / name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), record['sha256'])
                self.assertEqual(len(raw), record['bytes'])
                if name.endswith('.result.json'):
                    self.assertEqual(json.loads(raw), result)
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), summary['evidenceDigest'])

    def test_default_emit_preserves_full_json_and_output(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'MAESTRO_CI_DIAGNOSTICS': 'false'}):
            output = Path(temp) / 'result.json'
            stream = io.StringIO()
            result = {'schema': 1, 'status': 'allowed', 'complete': ['value'] * 10000}
            with redirect_stdout(stream):
                common.emit(result, output)
            self.assertEqual(stream.getvalue(), output.read_text())
            self.assertEqual(json.loads(stream.getvalue()), result)

    def test_failed_destination_retains_full_evidence_in_same_execution(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp}):
            product = Path(temp) / 'product.json'
            product.write_text('{}')
            output = Path(temp) / 'destination.json'
            value = {'schema': 1, 'status': 'conflict', 'expected': {'one': 'hash'}, 'observed': {'one': 'other'}}
            with patch.object(sys, 'argv', ['destinations.py', 'cache', '--product', str(product), '--output', str(output)]), patch.object(destinations, 'cache', return_value=value) as inspect:
                stream = io.StringIO()
                with redirect_stdout(stream), self.assertRaises(SystemExit):
                    destinations.main()
                self.assertEqual(inspect.call_count, 1)
                self.assertEqual(json.loads(output.read_text()), value)
                self.assertEqual(json.loads(stream.getvalue())['status'], 'conflict')
                results = list((Path(temp) / 'publication-diagnostics').glob('*.result.json'))
                self.assertEqual(len(results), 1)
                self.assertEqual(json.loads(results[0].read_text()), value)

    def test_shell_preserves_original_failure_and_emits_no_github_output(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'destination.py'
            calls = Path(temp) / 'calls'
            output = Path(temp) / 'github-output'
            source.write_text(f'from pathlib import Path\nPath({str(calls)!r}).open("a").write("call\\n")\nprint(\'{{"status":"conflict","expected":{{"full":"evidence"}}}}\')\nraise SystemExit(17)\n')
            result = subprocess.run(['bash', str(ROOT / 'nix/automation/publication-inspect.sh')], env=dict(
                os.environ, PUBLICATION_DESTINATIONS_SOURCE=str(source), DECISION_PRODUCT='unused',
                PUBLICATION_DESTINATION='cache', GITHUB_OUTPUT=str(output)), text=True, capture_output=True)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertEqual(json.loads(result.stdout)['expected'], {'full': 'evidence'})
            self.assertEqual(calls.read_text(), 'call\n')
            self.assertFalse(output.exists())

    def test_ci_errors_do_not_leak_exception_argv(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp}), patch.object(sys, 'argv', ['publication.py']):
            def fail():
                raise subprocess.CalledProcessError(1, ['tool', '--authorization', 'secret-sentinel'])
            stream = io.StringIO()
            with redirect_stderr(stream):
                self.assertEqual(common.run(fail), 2)
            self.assertNotIn('secret-sentinel', stream.getvalue())
            for path in (Path(temp) / 'publication-diagnostics').iterdir():
                self.assertNotIn('secret-sentinel', path.read_text())


if __name__ == '__main__':
    unittest.main()
