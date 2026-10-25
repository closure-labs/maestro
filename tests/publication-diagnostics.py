#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Same-execution evidence, bounded summaries and original shell failure status."""
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import datetime as dt
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
import diagnostic_artifacts as artifacts
import diagnostic_logs
import operations
from concurrent.futures import ThreadPoolExecutor
import destinations


class Diagnostics(unittest.TestCase):
    def setUp(self):
        display = patch.dict(diagnostics.GATE_DISPLAY, {}, clear=True)
        display.start()
        self.addCleanup(display.stop)
        for values in (diagnostics.COUNTERS, diagnostics.PROFILES, diagnostics.requests.ROWS, diagnostics.requests.INSPECTIONS):
            isolated = patch.dict(values, {}, clear=True)
            isolated.start()
            self.addCleanup(isolated.stop)

    def test_release_refreshes_same_scopes_before_assets_and_completion(self):
        workflow = json.loads(subprocess.check_output(
            ['yq', '-o=json', '.', str(ROOT / '.github/workflows/release-publication.yml')], text=True))
        steps = workflow['jobs']['publish']['steps']
        indexed = {step['id']: (index, step) for index, step in enumerate(steps) if 'id' in step}
        for prefix in ('assets-', 'completion-'):
            for scope in ('authority', 'upstream'):
                original = indexed[scope][1]
                refreshed = indexed[prefix + scope][1]
                self.assertEqual(refreshed['uses'], original['uses'])
                self.assertEqual(refreshed['with'], original['with'])
        asset_step = next(i for i, step in enumerate(steps)
                          if step.get('name') == 'Reconcile and publish exact approved hosted bytes')
        journal_step = next(i for i, step in enumerate(steps)
                            if step.get('name') == 'Record verified immutable GitHub publication')
        self.assertLess(indexed['assets-upstream'][0], asset_step)
        self.assertLess(asset_step, indexed['completion-authority'][0])
        self.assertLess(indexed['completion-upstream'][0], journal_step)
        self.assertIn('steps.assets-authority.outputs.token', steps[asset_step]['env']['GH_TOKEN'])
        self.assertIn('steps.completion-authority.outputs.token', steps[journal_step]['env']['GH_TOKEN'])

    def test_authority_http_status_is_retained_without_exception_text(self):
        error = common.authority.AuthorityAPIError('private-url credential-secret', 401)
        with patch.object(diagnostics, 'record', return_value='safe-summary') as record, \
                redirect_stderr(io.StringIO()) as output:
            def fail():
                raise error
            self.assertEqual(common.run(fail), 2)
        self.assertEqual(record.call_args.args[0]['httpStatus'], 401)
        self.assertNotIn('credential-secret', json.dumps(record.call_args.args[0]) + output.getvalue())

    def test_duplicate_occurrences_keep_exact_bytes_and_one_object(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
        }):
            result = {'status': 'covered', 'details': ['full result'] * 5000}
            summaries = [json.loads(diagnostics.record(result, kind)) for kind in ('gate', 'publication', 'handoff')]
            diagnostics.manifest()
            root = Path(temp) / 'publication-diagnostics'
            manifest = artifacts.verify(root)
            self.assertEqual(manifest['schema'], 2)
            self.assertEqual(len(list(root.rglob('*.result.json'))), 1)
            self.assertEqual(len(manifest['occurrences']), 3)
            raw = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
            for summary in summaries:
                self.assertEqual((root / summary['resultReference']).read_bytes(), raw)
                self.assertEqual(summary['evidenceDigest'], hashlib.sha256(raw).hexdigest())

    def test_v1_v2_readers_retain_equivalent_evidence(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
        }):
            result = {'status': 'verified', 'complete': [1, 2, 3]}
            summary = json.loads(diagnostics.record(result, 'publication'))
            diagnostics.manifest()
            root = Path(temp) / 'publication-diagnostics'
            v2 = artifacts.verify(root)
            legacy = Path(temp) / 'legacy'
            legacy.mkdir()
            name = 'a' * 32
            summary.pop('resultReference')
            (legacy / (name + '.summary.json')).write_text(json.dumps(summary) + '\n')
            raw = (root / v2['occurrences'][0]['resultReference']).read_bytes()
            (legacy / (name + '.result.json')).write_bytes(raw)
            (legacy / 'manifest.json').write_text(json.dumps({'schema': 1, 'files': {
                member.name: artifacts.fingerprint(legacy, member.name) for member in legacy.iterdir()}}))
            self.assertEqual(artifacts.verify(legacy)['schema'], 1)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), summary['evidenceDigest'])

    def test_concurrent_occurrences_use_atomic_objects(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
        }):
            with ThreadPoolExecutor(max_workers=8) as workers:
                summaries = list(workers.map(lambda _: diagnostics.record({'status': 'covered', 'data': 'x' * 5000}, 'gate'), range(32)))
            diagnostics.manifest()
            root = Path(temp) / 'publication-diagnostics'
            manifest = artifacts.verify(root)
            self.assertEqual(len(manifest['occurrences']), 32)
            self.assertEqual(len(list(root.rglob('*.result.json'))), 1)
            self.assertEqual(len({json.loads(value)['resultReference'] for value in summaries}), 1)
            self.assertFalse(list(root.rglob('.pending-*')))

    def test_separate_processes_share_objects_without_losing_occurrences(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp,
            'PYTHONPATH': str(ROOT / 'nix/automation/decisions')
        }):
            script = 'import diagnostics; diagnostics.record({"status":"covered"}, "gate")'
            children = [subprocess.Popen([sys.executable, '-c', script]) for _ in range(4)]
            for child in children:
                self.assertEqual(child.wait(timeout=10), 0)
            diagnostics.manifest()
            root = Path(temp) / 'publication-diagnostics'
            value = artifacts.verify(root)
            self.assertEqual(len(value['occurrences']), 4)
            self.assertEqual(len({row['execution'] for row in value['occurrences']}), 4)
            self.assertEqual(len(list(root.rglob('*.result.json'))), 1)

    def test_explicit_api_retry_is_distinct_from_wrappers_and_http_attempts(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
        }), patch.dict(diagnostics.PROFILES, {}, clear=True):
            replies = [b'HTTP/2.0 503 Unavailable\r\n\r\n{}', b'HTTP/2.0 200 OK\r\n\r\n{}']
            def transport(*args, **kwargs):
                kwargs['stdout'].write(replies.pop(0))
                return subprocess.CompletedProcess(args, 0)
            with patch.object(common.authority.operations, 'run', side_effect=transport), patch.object(common.authority.time, 'sleep'):
                self.assertEqual(common.authority.github_api('private-credential-sentinel'), {})
            api = diagnostics.PROFILES['transport']['github-api']
            self.assertEqual((api['wrapperCalls'], api['explicitRetries']), (1, 1))
            self.assertGreater(api['capturedBytes'], 0)
            self.assertEqual(api['subprocessLaunches'], 0)  # The fixture supplied replies, not children.
            self.assertIsNone(api['httpAttempts'])
            diagnostics.record({'status': 'covered'}, 'gate')
            diagnostics.manifest()
            self.assertNotIn('private-credential-sentinel', (Path(temp) / 'publication-diagnostics/manifest.json').read_text())

    def test_native_health_records_the_failing_boundary(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
        }):
            now = dt.datetime.now(dt.timezone.utc)
            scan = {'schema': 1, 'repository': 'closure-labs/maestro', 'revision': 'a' * 40,
                    'profiles': {'maestro': {}}, 'scannedAt': (now - dt.timedelta(hours=2)).isoformat(),
                    'expiresAt': (now - dt.timedelta(hours=1)).isoformat()}
            path = Path(temp) / 'scans.json'
            path.write_text(json.dumps(scan))
            with diagnostics.boundary('handoff'), self.assertRaisesRegex(ValueError, 'Expired or future native health'):
                common.scans(path, {'repository': 'closure-labs/maestro', 'profiles': ['maestro']})
            events = [json.loads(p.read_text()) for p in (Path(temp) / 'publication-diagnostics').glob('*.freshness.json')]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]['boundary'], 'handoff')
            self.assertTrue(events[0]['expired'])
            self.assertLess(events[0]['remainingSeconds'], 0)

    def test_missing_corrupt_and_conflicting_objects_fail_closed(self):
        for mutation in ('missing', 'corrupt', 'symlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
                'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
            }):
                result = {'status': 'covered'}
                summary = json.loads(diagnostics.record(result, 'gate'))
                diagnostics.manifest()
                root = Path(temp) / 'publication-diagnostics'
                target = root / summary['resultReference']
                target.unlink()
                if mutation == 'corrupt':
                    target.write_text('corrupt')
                elif mutation == 'symlink':
                    target.symlink_to(root / 'manifest.json')
                with self.assertRaises((ValueError, OSError)):
                    artifacts.verify(root)
                if mutation != 'missing':
                    with self.assertRaises((ValueError, OSError)):
                        diagnostics.record(result, 'gate')

    def test_unsafe_paths_and_symlink_directories_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('../outside', '/absolute', 'objects/../outside', 'objects//x', 'objects/bad.result.json'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    artifacts.open_member(root, name)
            (root / 'objects').symlink_to(root, target_is_directory=True)
            with self.assertRaises((ValueError, OSError)):
                artifacts.store(root, b'full result')
            (root / 'publication-diagnostics').symlink_to(root, target_is_directory=True)
            with patch.dict(os.environ, {'RUNNER_TEMP': temp}), self.assertRaises(ValueError):
                diagnostics.directory()

    def test_nested_manifest_is_an_unexpected_member(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
        }):
            diagnostics.record({'status': 'covered'}, 'gate')
            diagnostics.manifest()
            root = Path(temp) / 'publication-diagnostics'
            (root / 'objects/manifest.json').write_text('{}')
            with self.assertRaises(ValueError):
                artifacts.verify(root)
            with self.assertRaises(ValueError):
                diagnostics.manifest()

    def test_profiles_are_fixed_categories_and_capture_bytes_without_argv(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
        }), patch.dict(diagnostics.PROFILES, {}, clear=True):
            output = operations.run([sys.executable, '-c', 'print("private-credential-sentinel")'],
                                    timeout=10, capture_output=True)
            diagnostics.profile('transport', 'github-api', wrappers=1, retries=2, reused=1024)
            diagnostics.record({'status': 'covered'}, 'gate')
            diagnostics.manifest()
            root = Path(temp) / 'publication-diagnostics'
            manifest = artifacts.verify(root)
            profile = manifest['profiles']['transport']['other']
            self.assertEqual((profile['calls'], profile['subprocessLaunches'], profile['capturedBytes']), (1, 1, len(output.stdout)))
            api = manifest['profiles']['transport']['github-api']
            self.assertEqual((api['wrapperCalls'], api['explicitRetries'], api['immutableBytesReused']), (1, 2, 1024))
            self.assertIsNone(api['httpAttempts'])
            self.assertIsNone(api['wireBytes'])
            for member in root.rglob('*.json'):
                self.assertNotIn('private-credential-sentinel', member.read_text())
            with self.assertRaises(ValueError):
                diagnostics.profile('transport', 'https://credential-sentinel')

    def test_freshness_records_observed_boundary_without_guessing_selection(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
        }):
            with diagnostics.boundary('selection'):
                diagnostics.freshness(10, True, False)
            with diagnostics.boundary('handoff'):
                diagnostics.freshness(-5, True, False)
            events = [json.loads(path.read_text()) for path in (Path(temp) / 'publication-diagnostics').glob('*.freshness.json')]
            self.assertEqual({(e['boundary'], e['expired']) for e in events}, {('selection', False), ('handoff', True)})
            self.assertNotIn('initially-stale', json.dumps(events))

    def test_successful_helper_retains_profiles_without_changing_full_stdout(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
        }), patch.dict(diagnostics.PROFILES, {}, clear=True), patch.dict(diagnostics.COUNTERS, {}, clear=True), \
             patch.object(sys, 'argv', ['decision-handoff-fetch.py']):
            def helper():
                common.command([sys.executable, '-c', 'print("{}")'])
                diagnostics.count('apiWrapperInvocations', 3)
                common.emit({'complete': 'original full output'})
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(common.run(helper), 0)
            self.assertEqual(json.loads(stream.getvalue()), {'complete': 'original full output'})
            diagnostics.manifest()
            root = Path(temp) / 'publication-diagnostics'
            manifest = artifacts.verify(root)
            self.assertEqual(manifest['occurrences'], [])
            self.assertEqual(manifest['profiles']['transport']['other']['subprocessLaunches'], 1)
            self.assertEqual(manifest['measurements']['apiWrapperInvocations'], 3)

    def test_original_log_attribution_is_a_complete_byte_partition(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'original.log'
            raw = (b'2026-10-24T00:00:00.1Z private-sentinel\n'
                   b'2026-10-24T00:00:01.1Z monitor output\n'
                   b'2026-10-24T00:00:02.1Z cleanup output\n'
                   b'unattributed bytes\n')
            path.write_bytes(raw)
            job = {'status': 'completed', 'started_at': '2026-10-24T00:00:00Z', 'completed_at': '2026-10-24T00:00:03Z', 'steps': [
                {'name': name, 'started_at': f'2026-10-24T00:00:0{second}Z', 'completed_at': f'2026-10-24T00:00:0{second + 1}Z'}
                for second, name in enumerate(('Publish verified realized closures', 'Monitor hosted runner', 'Post Set up Nix'))]}
            value = diagnostic_logs.measure(path, job)
            self.assertEqual(value['rawJobLogBytes'], len(raw))
            self.assertEqual(value['rawJobLogSha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(sum(value['bytesByCategory'].values()), len(raw))
            self.assertTrue(all(value['bytesByCategory'][key] for key in ('native', 'runner-monitoring', 'cleanup', 'unattributed')))
            self.assertNotIn('private-sentinel', json.dumps(value))
            job['status'] = 'in_progress'
            with self.assertRaises(ValueError):
                diagnostic_logs.measure(path, job)

    def test_packaged_journal_filename_retains_exact_result(self):
        result = {'schema': 2, 'productHash': 'b' * 64, 'steps': {'cache': 'complete'}, 'receipts': {}}
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp}), \
             patch.object(sys, 'argv', ['/nix/store/' + 'a' * 32 + '-publication-journal.py']):
            stream = io.StringIO()
            with redirect_stdout(stream):
                common.emit(result)
            self.assertEqual(json.loads(stream.getvalue())['kind'], 'publication-journal')
            files = list((Path(temp) / 'publication-diagnostics').rglob('*.result.json'))
            self.assertEqual(len(files), 1)
            self.assertEqual(json.loads(files[0].read_text()), result)

    def test_display_context_never_reuses_status_or_crosses_product_identity(self):
        product = 'b' * 64
        gate = {'status': 'covered', 'productHash': product, 'rootCount': 61, 'findingCount': 302,
                'producer': {'revision': 'a' * 40, 'runId': 123, 'runAttempt': 2}}
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp}):
            diagnostics.record(gate, 'gate', logged=False)
            for kind in ('publication', 'handoff', 'publication-journal'):
                value = json.loads(diagnostics.record({'status': 'blocked', 'productHash': product}, kind))
                self.assertEqual(value['status'], 'blocked')
                self.assertEqual((value['producerRun'], value['rootCount'], value['findingCount']), (123, 61, 302))
            other = json.loads(diagnostics.record({'status': 'covered', 'productHash': 'c' * 64}, 'publication'))
            self.assertIsNone(other['producerRun'])
            self.assertIsNone(other['findingCount'])

    def test_manifest_captures_only_valid_current_receipts_and_effective_flags(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp,
            'MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED': 'true', 'PUBLICATION_REQUIRE_VERIFIED': 'true'
        }):
            receipt = {'schema': 1, 'productHash': 'b' * 64, 'destination': 'cache', 'status': 'verified',
                       'expected': {'root': 'hash'}, 'observed': {'root': 'hash'},
                       'verifiedAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'verifier': 'a' * 64}
            raw = (json.dumps(receipt) + '\n').encode()
            (Path(temp) / 'cache-receipt.json').write_bytes(raw)
            (Path(temp) / 'flakehub-receipt.json').write_text('{"authorization":"private-sentinel"}')
            (Path(temp) / 'github-receipt.json').write_text('[]')
            (Path(temp) / 'unrelated.env').write_text('private-sentinel')
            diagnostics.manifest()
            root = Path(temp) / 'publication-diagnostics'
            manifest = json.loads((root / 'manifest.json').read_text())
            self.assertEqual((root / 'cache-receipt.json').read_bytes(), raw)
            self.assertFalse((root / 'flakehub-receipt.json').exists())
            self.assertEqual(manifest['receiptCapture']['flakehub'], 'invalid')
            self.assertEqual(manifest['receiptCapture']['github'], 'invalid')
            self.assertTrue(manifest['experiments']['MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED'])
            self.assertTrue(manifest['verifiedDestinationsRequired'])
            self.assertNotIn('private-sentinel', (root / 'manifest.json').read_text())

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
                results = list((Path(temp) / 'publication-diagnostics').rglob('*.result.json'))
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
        for caller in ('publication.py', 'decision-handoff-fetch.py', 'decision-retained.py'):
            with self.subTest(caller=caller), tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
                'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp
            }), patch.object(sys, 'argv', [caller]):
                def fail():
                    raise subprocess.CalledProcessError(1, ['tool', '--authorization', 'secret-sentinel' * 10000])
                stream = io.StringIO()
                with redirect_stderr(stream):
                    self.assertEqual(common.run(fail), 2)
                self.assertLessEqual(len(stream.getvalue().encode()), 4096)
                summary = json.loads(stream.getvalue())
                self.assertEqual(summary['status'], 'blocked')
                self.assertEqual(summary['kind'], 'publication' if caller == 'publication.py' else 'admission')
                results = list((Path(temp) / 'publication-diagnostics').rglob('*.result.json'))
                self.assertEqual(len(results), 1)
                self.assertEqual(json.loads(results[0].read_text())['errorType'], 'CalledProcessError')
                for path in (Path(temp) / 'publication-diagnostics').rglob('*'):
                    if not path.is_file():
                        continue
                    self.assertNotIn('secret-sentinel', path.read_text())
                self.assertNotIn('secret-sentinel', stream.getvalue())

    def test_helper_health_failure_retains_known_safe_reason_and_manifest_binding(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp,
            'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'
        }), patch.object(sys, 'argv', ['decision-handoff-fetch.py']):
            def fail():
                raise ValueError('Expired or future native health')
            with redirect_stderr(io.StringIO()):
                self.assertEqual(common.run(fail), 2)
            root = Path(temp) / 'publication-diagnostics'
            results = list(root.rglob('*.result.json'))
            self.assertEqual(len(results), 1)
            result = json.loads(results[0].read_text())
            self.assertEqual(result['reason'], 'native-health-expired-or-future')
            diagnostics.manifest()
            manifest = json.loads((root / 'manifest.json').read_text())
            self.assertEqual((manifest['source'], manifest['run'], manifest['attempt']), ('a' * 40, '123', '2'))
            self.assertEqual(manifest['files'][results[0].relative_to(root).as_posix()]['sha256'], hashlib.sha256(results[0].read_bytes()).hexdigest())

    def test_default_helper_failure_output_and_status_remain_complete(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'MAESTRO_CI_DIAGNOSTICS': 'false', 'RUNNER_TEMP': temp
        }), patch.object(sys, 'argv', ['decision-handoff-fetch.py']):
            def fail():
                raise ValueError('original native detail')
            stream = io.StringIO()
            with redirect_stderr(stream):
                self.assertEqual(common.run(fail), 2)
            self.assertEqual(json.loads(stream.getvalue()), {'schema': 1, 'status': 'blocked', 'error': 'original native detail'})
            self.assertFalse((Path(temp) / 'publication-diagnostics').exists())


if __name__ == '__main__':
    unittest.main()
