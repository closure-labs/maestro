#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measurements reconcile without caching responses or changing native outcomes."""
from contextlib import redirect_stdout, redirect_stderr
from contextvars import copy_context
from concurrent.futures import ThreadPoolExecutor
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'modules/ci/authority/_source/decisions'))
import common
import diagnostics as d
import diagnostic_requests as r
import diagnostic_artifacts as artifacts
import destinations
import operations

spec = importlib.util.spec_from_file_location('journal_fixture', ROOT / 'modules/release/publication/_source/publication-journal.py')
journal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journal)
PATH = '/nix/store/' + '0' * 32 + '-fixture'
HASH = 'sha256-' + base64.b64encode(bytes(32)).decode()
PRODUCT = {'products': {'fixture': {'storePath': PATH, 'narHash': HASH}}, 'revision': 'a' * 40}
BODY = f'StorePath: {PATH}\nNarHash: {HASH}\nNarSize: 1\nURL: nar/fixture.nar.zst\nReferences: \n'.encode()


class Attribution(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        patches = [patch.dict(os.environ, MAESTRO_CI_DIAGNOSTICS='true', RUNNER_TEMP=self.temp.name),
                   *(patch.dict(value, {}, clear=True) for value in (d.COUNTERS, d.PROFILES, d.GATE_DISPLAY, r.ROWS, r.INSPECTIONS)),
                   patch.object(r, 'OVERFLOW', False)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def totals(self, field):
        return sum(row['counters'].get(field, 0) for row in r.snapshot()['rows'])

    def test_nested_phases_have_one_innermost_request_owner(self):
        with r.scope(stage='publication'), d.measuring('gatePhases', 'gate'):
            d.count('apiWrapperInvocations')
            with d.measuring('gatePhases', 'admission'):
                d.count('apiWrapperInvocations', 2)
            with d.measuring('gatePhases', 'refresh'):
                d.count('apiWrapperInvocations', 3)
        self.assertEqual(self.totals('apiWrapperInvocations'), 6)
        self.assertEqual({x['labels']['phase']: x['counters']['apiWrapperInvocations'] for x in r.snapshot()['rows']},
                         {'gate': 1, 'admission': 2, 'refresh': 3})
        self.assertEqual(r.OWNER.get(), r.DEFAULT)

    def test_worker_context_and_additive_totals(self):
        with r.scope(stage='destinations', phase='refresh', purpose='cache-metadata'):
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(copy_context().run, d.count, 'publicTransportInvocations') for _ in range(100)]
                for future in futures:
                    future.result()
        self.assertEqual(self.totals('publicTransportInvocations'), 100)
        self.assertEqual(len(r.snapshot()['rows']), 1)
        self.assertEqual(r.snapshot()['rows'][0]['labels']['phase'], 'refresh')

    def test_snapshots_reconcile_while_workers_update_counters(self):
        def worker():
            for _ in range(50):
                d.count('apiWrapperInvocations')
                d.profile('transport', 'github-api', wrappers=1)
                d.snapshot()
                r.validate(artifacts.read_json(d.directory(), d.EXECUTION + '.profile.json', 1024 * 1024))
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: worker(), range(4)))
        self.assertEqual(self.totals('apiWrapperInvocations'), 200)

    def test_fixed_endpoint_classes_never_retain_endpoint_or_query(self):
        cases = {'git/ref/heads/main': 'protected-ref-tree', 'git/trees/abc': 'protected-ref-tree',
                 'git/blobs/abc': 'immutable-blob', 'rules/branches/main': 'policy-rules',
                 'commits': 'proposal-origin', 'commits/abc/pulls': 'proposal-origin',
                 'pulls/1': 'pr-identity-files', 'pulls/1/files': 'pr-identity-files',
                 'pulls/1/reviews': 'review-history', 'collaborators/private-login/permission': 'repository-permission',
                 'compare/a...b': 'source-ancestry', 'actions/runs/123': 'producer-attestation',
                 'contents/publications/private-name.json': 'journal-read'}
        for suffix, purpose in cases.items():
            with r.github_scope('repos/private-owner/private-repo/' + suffix + '?token=private-sentinel'):
                self.assertEqual(r.OWNER.get()['purpose'], purpose)
                d.count('apiWrapperInvocations')
        for endpoint, purpose in [('orgs/private/teams/admin', 'team-inventory'),
                                  ('orgs/private/teams/admin/members', 'team-inventory'),
                                  ('orgs/private/teams/admin/memberships/private-login', 'active-membership')]:
            self.assertEqual(r.github_purpose(endpoint), purpose)
        raw = json.dumps(r.snapshot())
        for secret in ('private-', 'repos/', '?token', 'https:', 'argv', 'headers'):
            self.assertNotIn(secret, raw)

    def test_current_and_historical_authority_are_separate(self):
        @r.authority
        def verify(*args, **kwargs):
            d.count('apiWrapperInvocations')
        verify(require_live_review=True)
        verify(require_live_review=False)
        self.assertEqual({x['labels']['authority'] for x in r.snapshot()['rows']}, {'current', 'historical'})

    def test_body_options_without_explicit_method_are_not_reported_as_get(self):
        for args, expected in [(['gh', 'api', 'repos/o/r/issues', '-f', 'body=private-sentinel'], 'other'),
                               (['gh', 'api', 'graphql', '-f', 'query=private-sentinel'], 'other'),
                               (['gh', 'api', '--method', 'PUT', 'repos/o/r/contents/x', '--input', '-'], 'PUT')]:
            with r.process_scope(args):
                self.assertEqual(r.OWNER.get()['method'], expected)
                d.count('apiWrapperInvocations')
        self.assertNotIn('private-sentinel', json.dumps(r.snapshot()))

    def test_retry_count_is_not_wrapper_or_http_attempt_count(self):
        replies = [b'HTTP/2.0 503 Unavailable\r\n\r\n{}', b'HTTP/2.0 200 OK\r\n\r\n{}']
        def transport(*args, **kwargs):
            kwargs['stdout'].write(replies.pop(0))
            return subprocess.CompletedProcess(args, 0)
        with patch.object(operations, 'run', side_effect=transport), patch.object(common.authority.time, 'sleep'):
            self.assertEqual(common.authority.github_api('repos/o/r/pulls/1/reviews'), {})
        self.assertEqual(self.totals('apiWrapperInvocations'), 1)
        self.assertEqual(self.totals('apiTransportInvocations'), 2)
        self.assertEqual(sum(x['transport'].get('explicitRetries', 0) for x in r.snapshot()['rows']), 1)
        self.assertIsNone(r.snapshot()['httpAttempts'])
        self.assertIsNone(r.snapshot()['wireBytes'])

    def test_journal_calls_are_measured_without_changing_subprocess_contract(self):
        result = subprocess.CompletedProcess([], 0, '{}', '')
        with patch.object(journal.subprocess, 'run', return_value=result) as run:
            with r.scope(purpose='journal-readback'):
                self.assertEqual(journal.api('repos/o/r/contents/publications/x.json'), {})
        self.assertEqual(run.call_args.kwargs['timeout'], 180)
        self.assertEqual(self.totals('apiWrapperInvocations'), 1)
        self.assertEqual(self.totals('apiTransportInvocations'), 1)
        row = r.snapshot()['rows'][0]
        self.assertEqual(row['labels']['purpose'], 'journal-readback')
        self.assertEqual(row['transport']['subprocessLaunches'], 1)
        self.assertEqual(row['transport']['capturedBytes'], 2)

    def test_journal_timeout_retains_original_exception_and_launch(self):
        error = subprocess.TimeoutExpired(['private-sentinel'], 180)
        with patch.object(journal.subprocess, 'run', side_effect=error):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                journal.api('repos/o/r/contents/publications/x.json')
        self.assertIs(caught.exception, error)
        self.assertEqual(sum(x['transport'].get('subprocessLaunches', 0) for x in r.snapshot()['rows']), 1)
        self.assertNotIn('private-sentinel', json.dumps(r.snapshot()))

    def test_cache_fallback_and_independent_inspections(self):
        def read(url):
            d.count('publicTransportInvocations')
            return (404, b'') if url.startswith('https://maestro.') else (200, BODY)
        for _ in range(2):
            self.assertEqual(destinations.cache(PRODUCT, 'https://maestro.cachix.org', read,
                                               upstreams=('https://cache.nixos.org',))['status'], 'verified')
        self.assertEqual(self.totals('publicTransportInvocations'), 4)
        inspections = r.snapshot()['inspections']
        self.assertEqual(len(inspections), 2)
        for value in inspections:
            self.assertEqual(value['distinctPaths'], 1)
            self.assertEqual(value['requests'], {'primary/GET/0/missing': 1, 'nixos-upstream/GET/1/found': 1})
        self.assertEqual({x['labels']['inspection'] for x in r.snapshot()['rows']}, {'0', '1'})

    def test_cache_observes_mutation_and_does_not_cache_observations(self):
        self.assertEqual(destinations.cache(PRODUCT, 'https://maestro.cachix.org', lambda _: (200, BODY))['status'], 'verified')
        self.assertEqual(destinations.cache(PRODUCT, 'https://maestro.cachix.org', lambda _: (404, b''))['status'], 'missing')
        self.assertEqual(r.snapshot()['inspections'][1]['requests'], {'primary/GET/0/missing': 1})

    def test_unavailable_and_malformed_cache_results_keep_original_behavior(self):
        with patch.object(destinations, 'http'):
            def unavailable(url):
                raise subprocess.TimeoutExpired(['private-sentinel'], 1)
            self.assertEqual(destinations.cache(PRODUCT, 'https://maestro.cachix.org', unavailable)['status'], 'unavailable')
        with self.assertRaisesRegex(ValueError, 'Malformed public cache metadata'):
            destinations.cache(PRODUCT, 'https://maestro.cachix.org', lambda _: (200, b'malformed'))
        rows = r.snapshot()['inspections']
        self.assertEqual(rows[0]['requests'], {'primary/GET/0/unavailable': 1})
        self.assertEqual(rows[1]['outcome'], 'failure')

    def test_stage_started_record_is_unknown_until_native_completion(self):
        def main():
            records = list(d.directory().glob('*.stage.json'))
            self.assertEqual(len(records), 1)
            value = json.loads(records[0].read_text())
            self.assertEqual(value['outcome'], 'unknown')
            self.assertIsNone(value['elapsedSeconds'])
            print('original stdout')
        stream = io.StringIO()
        with patch.object(sys, 'argv', ['publication.py']), redirect_stdout(stream):
            self.assertEqual(common.run(main), 0)
        self.assertEqual(stream.getvalue(), 'original stdout\n')
        value = json.loads(next(d.directory().glob('*.stage.json')).read_text())
        self.assertEqual((value['stage'], value['outcome'], value['exitCode']), ('publication', 'success', 0))
        self.assertGreaterEqual(value['elapsedSeconds'], 0)

    def test_failure_and_system_exit_are_not_masked_by_stage_records(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(common.run(lambda: (_ for _ in ()).throw(ValueError('private-sentinel'))), 2)
        failure = json.loads(next(d.directory().glob('*.stage.json')).read_text())
        self.assertEqual((failure['outcome'], failure['exitCode']), ('failure', 2))
        @d.staged
        def fail():
            raise SystemExit(17)
        with patch.object(d, 'finish_stage', side_effect=OSError('unwritable')):
            with self.assertRaises(SystemExit) as caught:
                fail()
        self.assertEqual(caught.exception.code, 17)
        self.assertNotIn('private-sentinel', ''.join(p.read_text() for p in d.directory().glob('*.stage.json')))

    def test_unfinished_stage_can_be_retained_without_invented_outcome(self):
        @d.staged
        def main():
            return None
        with patch.object(d, 'finish_stage'):
            main()
        d.manifest()
        manifest = artifacts.verify(d.directory())
        value = artifacts.read_json(d.directory(), manifest['nativeStages'][0])
        self.assertEqual(value['outcome'], 'unknown')
        self.assertIsNone(value['elapsedSeconds'])

    def test_killed_native_process_retains_unknown_stage(self):
        script = 'import diagnostics as d,time\n@d.staged\ndef main():\n print("ready",flush=True)\n time.sleep(60)\nmain()\n'
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'modules/ci/authority/_source/decisions'))
        with subprocess.Popen([sys.executable, '-c', script], env=env, stdout=subprocess.PIPE, text=True) as child:
            try:
                self.assertEqual(child.stdout.readline().strip(), 'ready')
            finally:
                child.kill()
                child.wait(timeout=10)
        d.manifest()
        value = artifacts.read_json(d.directory(), artifacts.verify(d.directory())['nativeStages'][0])
        self.assertEqual(value['outcome'], 'unknown')
        self.assertIsNone(value['elapsedSeconds'])

    def test_duplicate_execution_profile_cannot_inflate_totals(self):
        d.count('apiWrapperInvocations')
        d.snapshot()
        source = d.directory() / (d.EXECUTION + '.profile.json')
        (d.directory() / ('f' * 32 + '.profile.json')).write_bytes(source.read_bytes())
        with self.assertRaisesRegex(ValueError, 'execution profile'):
            d.manifest()

    def test_fixed_label_and_capacity_bounds_do_not_drop_counts(self):
        with self.assertRaises(ValueError):
            with r.scope(purpose='https://private-sentinel'):
                pass
        with patch.object(r, 'MAX_ROWS', 1):
            for purpose in ('review-history', 'team-inventory', 'active-membership'):
                with r.scope(purpose=purpose):
                    d.count('apiWrapperInvocations')
        self.assertEqual(self.totals('apiWrapperInvocations'), 3)
        self.assertTrue(r.snapshot()['overflowed'])
        self.assertLessEqual(len(r.snapshot()['rows']), 2)

    def test_disabled_diagnostics_do_not_write_or_collect(self):
        with patch.dict(os.environ, MAESTRO_CI_DIAGNOSTICS='false'):
            common.run(lambda: d.count('apiWrapperInvocations'))
            destinations.cache(PRODUCT, 'https://maestro.cachix.org', lambda _: (200, BODY))
        self.assertEqual(r.snapshot()['rows'], [])
        self.assertEqual(r.snapshot()['inspections'], [])
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_child_profiles_and_repeated_parent_snapshots_count_once(self):
        script = 'import diagnostics as d; d.count("apiWrapperInvocations", 2); d.snapshot(); d.snapshot()'
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'modules/ci/authority/_source/decisions'))
        for _ in range(2):
            subprocess.run([sys.executable, '-c', script], env=env, check=True, timeout=10)
        d.count('apiWrapperInvocations', 3)
        summary = json.loads(d.record({'status': 'covered', 'unchanged': True}, 'gate'))
        d.snapshot()
        d.manifest()
        manifest = artifacts.verify(d.directory())
        self.assertEqual(manifest['measurements']['apiWrapperInvocations'], 7)
        self.assertEqual(len(manifest['requestProfiles']), 3)
        self.assertLessEqual(len(json.dumps(summary).encode()), 4096)
        total = sum(sum(row['counters'].get('apiWrapperInvocations', 0) for row in
                        artifacts.read_json(d.directory(), name, 1024 * 1024)['requests']['rows'])
                    for name in manifest['requestProfiles'])
        self.assertEqual(total, 7)

    def test_tampered_attribution_and_unmeasured_traffic_are_rejected(self):
        d.count('apiWrapperInvocations', 2)
        d.snapshot()
        path = d.directory() / (d.EXECUTION + '.profile.json')
        value = json.loads(path.read_text())
        r.validate(value)
        value['requests']['rows'][0]['counters']['apiWrapperInvocations'] = 1
        with self.assertRaisesRegex(ValueError, 'do not reconcile'):
            r.validate(value)
        value = json.loads(path.read_text())
        value['requests']['wireBytes'] = 42
        with self.assertRaises(ValueError):
            r.validate(value)

    def test_overflow_still_reconciles_transport_and_count_types_are_strict(self):
        d.count('apiWrapperInvocations')
        d.profile('transport', 'github-api', launches=1)
        d.snapshot()
        path = d.directory() / (d.EXECUTION + '.profile.json')
        for mutation in ('schema', 'count', 'overflow'):
            value = json.loads(path.read_text())
            if mutation == 'schema':
                value['requests']['schema'] = True
            elif mutation == 'count':
                value['requests']['rows'][0]['counters']['apiWrapperInvocations'] = 1.0
            else:
                value['requests']['overflowed'] = True
                value['requests']['rows'][0]['transport']['subprocessLaunches'] = 2
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                r.validate(value)
        value = json.loads(path.read_text())
        value['requests']['rows'][0]['labels']['purpose'] = 'private-sentinel'
        with self.assertRaises(ValueError):
            r.validate(value)


if __name__ == '__main__':
    unittest.main()
