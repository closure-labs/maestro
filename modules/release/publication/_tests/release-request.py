#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Adversarial request provenance and continuation ordering fixtures."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.environ['GITHUB_REPOSITORY'] = 'example/maestro'
spec = importlib.util.spec_from_file_location('request', Path(__file__).resolve().parents[4] / 'modules/release/publication/_source/release-request.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = 'a' * 40
INITIAL = 'b' * 40


def run(identity, workflow, source=SOURCE):
    return dict(id=identity, repository={'full_name': module.REPO}, head_repository={'full_name': module.REPO},
                event='workflow_dispatch', head_branch='main', path='.github/workflows/' + workflow,
                head_sha=source, status='completed', conclusion='success',
                display_title='Maestro release request 10', created_at=(module.NOW - module.dt.timedelta(minutes=5)).isoformat())


class Requests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / 'outputs'
        self.request = dict(schema_version=1, repository=module.REPO, request_run_id=10, source_sha=SOURCE,
                            tag='v1.2.3', version='1.2.3', created_at=module.NOW.isoformat(),
                            expires_at=(module.NOW + module.TTL).isoformat())
        self.origin, self.candidate = run(10, 'release.yml', INITIAL), run(20, 'ci.yml')
        self.request['expires_at'] = (module.timestamp(self.origin['created_at']) + module.TTL).isoformat()
        env = patch.dict(os.environ, GITHUB_OUTPUT=str(self.output), MAESTRO_RELEASE_CONTINUATION_ENABLED='true',
                         MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS='[]', GITHUB_REF='refs/heads/main',
                         GITHUB_EVENT_NAME='workflow_run', GITHUB_SHA=SOURCE,
                         RELEASE_REQUEST_RUN_ID='10', RELEASE_CANDIDATE_RUN_ID='20', GITHUB_RUN_ID='20')
        env.start()
        self.addCleanup(env.stop)

    def api(self, path, **kwargs):
        if path == 'actions/runs/10':
            return self.origin
        if path == 'actions/runs/20':
            return self.candidate
        if path.startswith('compare/'):
            return {'status': 'ahead'}
        if path.startswith('contents/VERSION'):
            return {'content': base64.b64encode(b'1.2.3\n').decode()}
        self.fail('Unexpected API: ' + path)

    def resolve(self):
        with patch.object(module, 'api', side_effect=self.api), patch.object(module, 'journal', return_value=self.request), \
                patch.object(module, 'published', return_value=False), patch.object(module.time, 'sleep'):
            module.resolve()
        return self.output.read_text()

    def test_successful_exact_candidate(self):
        output = self.resolve()
        self.assertIn('ready=true\n', output)
        self.assertIn('source_sha=' + SOURCE, output)
        self.assertIn('run_id=20\n', output)

    def test_published_duplicate_only_resumes_unfinished_version_advancement(self):
        for current, ready in [('1.2.3', True), ('1.2.4-dev.0', False), ('1.3.0', False)]:
            with self.subTest(current=current):
                def api(path):
                    if path == 'contents/VERSION?ref=main':
                        return {'content': base64.b64encode(current.encode()).decode()}
                    return self.api(path)
                self.output.unlink(missing_ok=True)
                with patch.object(module, 'api', side_effect=api), patch.object(module, 'journal', return_value=self.request), \
                        patch.object(module, 'published', return_value=True) as publication:
                    module.resolve()
                self.assertEqual(publication.call_count, 1)
                self.assertIn('ready=' + str(ready).lower() + '\n', self.output.read_text())
                if not ready:
                    self.assertEqual(self.output.read_text(), 'ready=false\n')

    def test_invalid_run_identity_rejected(self):
        for field, value in [('event', 'pull_request'), ('head_branch', 'evil'), ('head_sha', 'c' * 40),
                             ('path', '.github/workflows/untrusted.yml'), ('display_title', 'Maestro release request 11'),
                             ('head_repository', {'full_name': 'attacker/fork'})]:
            with self.subTest(field=field):
                original = copy.deepcopy(self.candidate)
                self.candidate[field] = value
                with self.assertRaises(ValueError):
                    self.resolve()
                self.candidate = original

    def test_no_completion_on_either_unfinished_or_failed_run(self):
        for target in (self.origin, self.candidate):
            for field, value in [('status', 'in_progress'), ('conclusion', 'failure'), ('conclusion', 'cancelled')]:
                with self.subTest(target=target['id'], field=field):
                    original = target[field]
                    target[field] = value
                    self.output.unlink(missing_ok=True)
                    if field == 'status':
                        with self.assertRaisesRegex(ValueError, 'timed out'):
                            self.resolve()
                    else:
                        self.assertEqual(self.resolve(), 'ready=false\n')
                    target[field] = original

    def test_explicit_completion_wait_is_bounded_and_requires_success(self):
        running = self.candidate | {'status': 'in_progress', 'conclusion': None}
        responses = [running, self.candidate]
        def api(path, **kwargs):
            return responses.pop(0) if path == 'actions/runs/20' else self.api(path)
        with patch.dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch'), \
                patch.object(module, 'api', side_effect=api), patch.object(module, 'journal', return_value=self.request), \
                patch.object(module, 'published', return_value=False), patch.object(module.time, 'sleep') as sleep:
            module.resolve()
        sleep.assert_called_once_with(5)
        self.assertIn('ready=true', self.output.read_text())
        self.output.unlink()
        self.candidate.update(status='in_progress', conclusion=None)
        with patch.object(module.time, 'sleep') as sleep, patch.object(module, 'api', side_effect=self.api), \
                patch.object(module, 'journal', return_value=self.request):
            with self.assertRaisesRegex(ValueError, 'timed out'):
                module.resolve()
        self.assertEqual(sleep.call_count, 24)
        self.assertFalse(self.output.exists())

    def test_origin_second_order_and_shared_poll_deadline(self):
        running = self.origin | {'status': 'in_progress', 'conclusion': None}
        responses = [running, self.origin]
        def api(path, **kwargs):
            return responses.pop(0) if path == 'actions/runs/10' else self.api(path)
        with patch.dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch'), \
                patch.object(module, 'api', side_effect=api), patch.object(module, 'journal', return_value=self.request), \
                patch.object(module, 'published', return_value=False), patch.object(module.time, 'sleep') as sleep:
            module.resolve()
        sleep.assert_called_once_with(5)
        self.assertIn('ready=true', self.output.read_text())
        running = self.candidate | {'status': 'in_progress', 'conclusion': None}
        with patch.object(module.time, 'monotonic', side_effect=[0, 5, 6]), \
                patch.object(module.time, 'sleep') as sleep, patch.object(module, 'api', return_value=self.candidate) as api:
            self.assertEqual(module.completion(running, 120), self.candidate)
        sleep.assert_called_once_with(5)
        api.assert_called_once_with('actions/runs/20', timeout=115)
        with patch.object(module.time, 'monotonic', return_value=121), patch.object(module, 'api') as api:
            with self.assertRaisesRegex(ValueError, 'timed out'):
                module.completion(running, 120)
        api.assert_not_called()

    def test_explicit_input_validation_and_protected_context(self):
        for env in [{'RELEASE_REQUEST_RUN_ID': '0'}, {'RELEASE_CANDIDATE_RUN_ID': '../20'},
                    {'RELEASE_CANDIDATE_RUN_ID': ''}, {'GITHUB_REF': 'refs/heads/evil'},
                    {'GITHUB_EVENT_NAME': 'pull_request'}]:
            with self.subTest(env=env), patch.dict(os.environ, **env):
                with self.assertRaises(ValueError):
                    self.resolve()

    def test_exact_request_retirement_preserves_other_requests(self):
        with patch.dict(os.environ, MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS='[10]'):
            self.assertEqual(self.resolve(), 'ready=false\n')
            with patch.object(module, 'recent', return_value=[self.origin]), patch.object(module, 'published') as published:
                module.pending()
                published.assert_not_called()
        for value in ['0', '*', '10,11', '../10', '-1', '[true]', '[1.0]', '["10"]', '[0]', '[-1]', '[[]]', '[10,10]', json.dumps(list(range(1, 18)))]:
            with self.subTest(value=value), patch.dict(os.environ, MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS=value):
                with self.assertRaises(ValueError):
                    self.resolve()
        with patch.dict(os.environ, MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS='[11]'):
            self.output.unlink()
            self.assertIn('ready=true', self.resolve())

    def test_signal_dispatches_only_exact_candidate_after_successful_verdict(self):
        verdict = dict(name='Required CI verdict', status='completed', conclusion='success')
        def api(path):
            if path.endswith('/jobs?per_page=100'):
                return {'total_count': 1, 'jobs': [verdict]}
            return self.api(path)
        def signal():
            with patch.dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch'), \
                    patch.object(module, 'api', side_effect=api), patch.object(module, 'journal', return_value=self.request), \
                    patch.object(module, 'command') as command:
                module.signal()
                command.assert_called_once_with('gh', 'workflow', 'run', 'release-continuation.yml', '--repo', module.REPO,
                                                '--ref', 'main', '-f', 'release_request_run_id=10', '-f', 'release_candidate_run_id=20')
        signal()
        self.origin.update(status='in_progress', conclusion=None)
        signal()
        self.origin.update(status='completed', conclusion='success')
        for env in [{'GITHUB_SHA': INITIAL}, {'RELEASE_REQUEST_RUN_ID': '0'}, {'GITHUB_RUN_ID': '../20'},
                    {'GITHUB_REF': 'refs/heads/evil'}, {'MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS': '[10]'},
                    {'MAESTRO_RELEASE_CONTINUATION_ENABLED': 'false'}]:
            with self.subTest(env=env), patch.dict(os.environ, **env):
                with self.assertRaises(ValueError):
                    signal()
        for conclusion in ['failure', 'cancelled', 'skipped', None]:
            verdict['conclusion'] = conclusion
            with self.assertRaises(ValueError):
                signal()
        verdict['conclusion'] = 'success'
        self.candidate['display_title'] = 'CI main'
        with self.assertRaises(ValueError):
            signal()

    def test_retirement_list_covers_two_origins_without_retiring_a_third(self):
        other = self.origin | {'id': 11}
        third = self.origin | {'id': 12}
        with patch.dict(os.environ, MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS='[10,11]'), \
                patch.object(module, 'recent', return_value=[self.origin, other]), \
                patch.object(module, 'published', return_value=False) as publication:
            module.pending()
            publication.assert_not_called()
            self.assertTrue(module.retired(10))
            self.assertTrue(module.retired(11))
            self.assertFalse(module.retired(12))
            with patch.object(module, 'recent', return_value=[self.origin, other, third]), \
                    patch.object(module, 'journal', return_value=self.request), \
                    patch.object(module, 'candidate', return_value=self.candidate):
                with self.assertRaisesRegex(ValueError, 'awaiting continuation'):
                    module.pending()
        with patch.dict(os.environ, MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS=json.dumps(list(range(1, 17)))):
            self.assertTrue(module.retired(16))
            self.assertFalse(module.retired(17))

    def test_expiry_and_main_ancestry(self):
        with patch.object(module, 'api', return_value={'status': 'diverged'}):
            with self.assertRaises(ValueError):
                module.validate(self.request, self.origin, self.candidate)
        self.request['expires_at'] = (module.NOW - module.TTL).isoformat()
        self.assertEqual(self.resolve(), 'ready=false\n')

    def test_source_version_mismatch(self):
        def api(path):
            if path.startswith('contents/'):
                return {'content': base64.b64encode(b'9.9.9').decode()}
            return self.api(path)
        with patch.object(module, 'api', side_effect=api):
            with self.assertRaises(ValueError):
                module.validate(self.request, self.origin, self.candidate)

    def test_journal_origin_lifetime_fields_and_single_document(self):
        def command(*args):
            (Path(args[-1]) / 'maestro-release-request.json').write_text(self.serialized)
            return ''
        artifacts = {'total_count': 1, 'artifacts': [{'name': 'maestro-release-request', 'expired': False}]}
        with patch.object(module, 'api', return_value=artifacts), patch.object(module, 'command', side_effect=command):
            self.serialized = json.dumps(self.request)
            self.assertEqual(module.journal(self.origin), self.request)
            for update in [{'request_run_id': 11}, {'repository': 'attacker/fork'}, {'source_sha': '../bad'},
                           {'tag': 'v9.9.9'}, {'extra': True}, {'expires_at': (module.NOW + module.TTL * 2).isoformat()}]:
                self.serialized = json.dumps(self.request | update)
                with self.assertRaises(ValueError):
                    module.journal(self.origin)
            self.serialized = json.dumps(self.request) + '\n' + json.dumps(self.request)
            with self.assertRaises(ValueError):
                module.journal(self.origin)

    def test_unexpired_pending_request_blocks_before_new_preparation(self):
        with patch.dict(os.environ, GITHUB_RUN_ID='30'), patch.object(module, 'recent', return_value=[self.origin]), \
                patch.object(module, 'journal', return_value=self.request), patch.object(module, 'candidate', return_value=self.candidate), \
                patch.object(module, 'published', return_value=False):
            with self.assertRaises(ValueError):
                module.pending()
            self.candidate['conclusion'] = 'failure'
            module.pending()

    def test_candidate_lookup_ambiguity_and_bounded_overflow(self):
        with patch.object(module, 'recent', return_value=[self.candidate, self.candidate]):
            with self.assertRaises(ValueError):
                module.candidate(self.request)
        with patch.object(module, 'api', return_value={'workflow_runs': [self.candidate] * 100}) as calls:
            with self.assertRaises(ValueError):
                module.recent('ci.yml')
            self.assertEqual(calls.call_count, 3)

    def test_create_expiry_is_bound_to_origin_not_late_journal_creation(self):
        original = Path.cwd()
        try:
            os.chdir(self.directory.name)
            with patch.dict(os.environ, GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch',
                            SOURCE_SHA=SOURCE, RELEASE_VERSION='1.2.3', RELEASE_TAG='v1.2.3', GITHUB_RUN_ID='10'), \
                    patch.object(module, 'api', return_value=self.origin):
                module.create()
            request = json.loads(Path('maestro-release-request.json').read_text())
            self.assertEqual(module.timestamp(request['expires_at']), module.timestamp(self.origin['created_at']) + module.TTL)
        finally:
            os.chdir(original)

    def test_published_identity_and_api_failure_are_not_ignored(self):
        response = type('Response', (), dict(returncode=0, stdout=json.dumps({'draft': False}), stderr=''))()
        with patch.object(module.subprocess, 'run', return_value=response), patch.object(module, 'api', return_value={'sha': SOURCE}):
            self.assertTrue(module.published(self.request))
        with patch.object(module.subprocess, 'run', return_value=response), patch.object(module, 'api', return_value={'sha': INITIAL}):
            with self.assertRaises(ValueError):
                module.published(self.request)
        response.returncode, response.stderr = 1, 'HTTP 403'
        with patch.object(module.subprocess, 'run', return_value=response):
            with self.assertRaises(ValueError):
                module.published(self.request)
        response.stderr = 'HTTP 404'
        with patch.object(module.subprocess, 'run', return_value=response):
            self.assertFalse(module.published(self.request))

    def test_disabled_pilot_rejected_before_mutation(self):
        with patch.dict(os.environ, MAESTRO_RELEASE_CONTINUATION_ENABLED='false', EVENT_CONTINUATION='true'):
            with self.assertRaises(ValueError):
                module.pending()
            with self.assertRaises(ValueError):
                module.create()

    def test_completion_order_and_unrelated_trigger(self):
        event = Path(self.directory.name) / 'event'
        event.write_text(json.dumps({'workflow_run': {'id': 10}}))
        with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event)):
            os.environ.pop('RELEASE_REQUEST_RUN_ID')
            os.environ.pop('RELEASE_CANDIDATE_RUN_ID')
            with patch.object(module, 'api', side_effect=self.api), patch.object(module, 'journal', return_value=self.request), \
                    patch.object(module, 'candidate', return_value=self.candidate), patch.object(module, 'published', return_value=False):
                module.resolve()
            self.assertIn('ready=true', self.output.read_text())
            event.write_text(json.dumps({'workflow_run': {'id': 20}}))
            self.output.unlink()
            self.assertIn('ready=true', self.resolve())
            self.candidate['display_title'] = 'CI main'
            self.output.unlink()
            self.assertEqual(self.resolve(), 'ready=false\n')


unittest.main()
