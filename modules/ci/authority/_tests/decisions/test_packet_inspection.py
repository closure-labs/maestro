#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact interrupted-write readback without registry/repository mutations."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / 'modules/ci/authority/_source/decisions'))
import packet_inspection as mod


class Inspection(unittest.TestCase):
    def setUp(self):
        self.request, self.descriptor = mod.reviewed_request(mod.REQUEST_PATH.read_bytes(), mod.REQUEST_HASH)
        self.commands = []
        self.logs = ('2026-11-01T00:00:00Z   CANDIDATE_RUN: 41262202226\n'
                     '2026-11-01T00:00:00Z   SECURITY_RECOVERY_REQUEST: ' +
                     json.dumps(self.request['originalRun']['recovery']) + '\n').encode()
        self.layers = [{'annotations': {'org.opencontainers.image.title': k},
                        'digest': 'sha256:' + v['sha256'], 'size': v['size']}
                       for k, v in self.request['descriptor']['files'].items()]
        self.layers.append({'annotations': {'org.opencontainers.image.title': 'decision-packet.json'},
                            'digest': 'sha256:' + self.request['descriptorBlobSha256'], 'size': len(self.descriptor)})
        self.responses = {}
        prefix = f'repos/{mod.REPOSITORY}/actions'
        old = self.request['originalRun']
        for identity, workflow, event, conclusion in ((old['id'], 'decisions', 'workflow_dispatch', 'cancelled'),
                                                       (41262202226, 'ci', 'push', 'success')):
            self.responses[f'{prefix}/runs/{identity}/attempts/1'] = {
                'id': identity, 'run_attempt': 1, 'head_sha': old['revision'], 'head_branch': 'main',
                'path': f'.github/workflows/{workflow}.yml', 'event': event, 'conclusion': conclusion,
                'status': 'completed', 'repository': {'id': mod.REPOSITORY_ID, 'full_name': mod.REPOSITORY},
                'head_repository': {'id': mod.REPOSITORY_ID, 'full_name': mod.REPOSITORY}}
        self.responses[f'{prefix}/jobs/{old["job"]}'] = {'id': old['job'], 'run_id': old['id'], 'run_attempt': 1,
            'head_sha': old['revision'], 'head_branch': 'main', 'name': 'reconcile', 'status': 'completed'}
        a = self.request['artifact']
        self.responses[f'{prefix}/artifacts/{a["id"]}'] = {'id': a['id'], 'name': 'maestro-security-report',
            'expired': False, 'digest': a['archiveSha256'], 'size_in_bytes': a['archiveBytes'],
            'workflow_run': {'id': 41262202226, 'head_sha': old['revision']}}
        self.responses[f'repos/{mod.REPOSITORY}/branches/main'] = {'protected': True}

    def api(self, endpoint):
        return copy.deepcopy(self.responses[endpoint])  # Unknown endpoint fails closed.

    def command(self, args, **kwargs):
        self.commands.append(args)
        if args[:2] == ['oras', 'login']:
            return b''
        if args[:3] == ['oras', 'manifest', 'fetch']:
            return json.dumps({'schemaVersion': 2, 'artifactType': mod.packets.TYPE, 'layers': self.layers}).encode()
        if args[:3] == ['oras', 'blob', 'fetch']:
            self.assertEqual(args[3], mod.REGISTRY + '@sha256:' + self.request['descriptorBlobSha256'])
            Path(args[args.index('--output') + 1]).write_bytes(self.descriptor)
            return b''
        if args[:5] == ['gh', 'api', '--method', 'GET', '--allow-escape-sequences']:
            self.assertEqual(args[5], f'repos/{mod.REPOSITORY}/actions/jobs/124731818265/logs')
            return self.logs
        self.fail('Write or unexpected command: ' + repr(args))

    def inspect(self):
        with mock.patch.object(mod, 'github_api', side_effect=self.api), \
             mock.patch.object(mod.packets, 'command', side_effect=self.command), \
             mock.patch.object(mod.packets, 'private_review_registry') as privacy, \
             mock.patch.object(mod.packets, 'metadata_reuse_enabled', return_value=False):
            result = mod.inspect(self.request, self.descriptor)
            privacy.assert_called_once_with()
            return result

    def test_verified_existing_reads_only_descriptor_not_closures(self):
        result = self.inspect()
        self.assertEqual(result['status'], 'verified-existing')
        self.assertFalse(result['authorization'])
        self.assertEqual(result['inventoryMembers'], 22)
        self.assertEqual(result['closurePayloadBytesDownloaded'], 0)
        self.assertEqual(sum(c[:3] == ['oras', 'blob', 'fetch'] for c in self.commands), 1)
        self.assertEqual(self.commands[1][3], mod.REGISTRY + ':packet-' + self.request['descriptorSha256'])
        self.assertTrue(self.commands[2][3].startswith(mod.REGISTRY + '@sha256:'))

    def test_request_confirmation_and_every_reviewed_binding_are_exact(self):
        for field in self.request:
            request = copy.deepcopy(self.request)
            del request[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                mod.reviewed_request(json.dumps(request).encode(), mod.REQUEST_HASH)
        for field in ('originalRun', 'artifact', 'descriptor'):
            request = copy.deepcopy(self.request); request[field]['extra'] = 'substitution'
            with self.assertRaises(ValueError):
                mod.reviewed_request(json.dumps(request).encode(), mod.REQUEST_HASH)
        for raw, confirmation in ((mod.REQUEST_PATH.read_bytes(), '0' * 64), (b'{}', mod.REQUEST_HASH),
                                  (b'x' * (mod.MAX_REQUEST + 1), mod.REQUEST_HASH),
                                  (b'{"schema":1,"schema":1}', mod.REQUEST_HASH)):
            with self.assertRaises(ValueError): mod.reviewed_request(raw, confirmation)

    def test_missing_extra_mutated_or_duplicate_manifest_members_reject(self):
        original = copy.deepcopy(self.layers)
        cases = [original[:-1], original + [original[0]], original[1:]]
        changed = copy.deepcopy(original); changed[0]['digest'] = 'sha256:' + '0' * 64; cases.append(changed)
        changed = copy.deepcopy(original); changed[0]['size'] += 1; cases.append(changed)
        changed = copy.deepcopy(original); changed[0]['annotations']['org.opencontainers.image.title'] = '../escape'; cases.append(changed)
        for layers in cases:
            self.layers = layers
            with self.subTest(layers=layers[-1]['size']), self.assertRaises(ValueError): self.inspect()
        self.assertFalse(any(c[:3] == ['oras', 'blob', 'fetch'] for c in self.commands))

    def test_producer_original_attempt_job_and_artifact_substitution_reject_before_registry(self):
        for endpoint, fields in self.responses.items():
            if endpoint.endswith('/branches/main'): continue
            for field in fields:
                old = copy.deepcopy(self.responses[endpoint][field])
                self.responses[endpoint][field] = None
                with self.subTest(endpoint=endpoint, field=field), self.assertRaises((ValueError, TypeError)):
                    self.inspect()
                self.responses[endpoint][field] = old
        self.assertFalse(any(c[0] == 'oras' for c in self.commands))

    def test_retained_request_logs_missing_ambiguous_changed_or_oversized_reject(self):
        good = self.logs
        for bad in (b'', good + good, good.replace(b'41262202226', b'41262202227'),
                    good.replace(b'accepted', b'revoked'), b'x' * (mod.MAX_LOG + 1)):
            self.logs = bad
            with self.assertRaises(ValueError): self.inspect()
        self.assertFalse(any(c[0] == 'oras' for c in self.commands))

    def test_descriptor_substitution_and_manifest_resource_bound_reject(self):
        self.descriptor = b'{}'
        with self.assertRaises(ValueError): self.inspect()
        self.setUp()
        self.layers[0]['size'] = 33 * 1024**3
        with self.assertRaises(ValueError): self.inspect()

    def test_workflow_is_manual_protected_main_read_only_and_has_no_mint(self):
        path = ROOT / '.github/workflows/decision-packet-inspection.yml'
        value = json.loads(subprocess.check_output(['yq', '-o=json', '.', str(path)], text=True))
        self.assertEqual(set(value['on']), {'workflow_dispatch'})
        self.assertEqual(value['permissions'], {'contents': 'read', 'actions': 'read', 'packages': 'read'})
        job = value['jobs']['inspect']
        self.assertIn("github.event_name == 'workflow_dispatch'", job['if'])
        self.assertIn("github.ref == 'refs/heads/main'", job['if'])
        self.assertIn("github.repository == 'closure-labs/maestro'", job['if'])
        self.assertNotIn('permissions', job)
        self.assertLessEqual(job['timeout-minutes'], 10)
        steps = job['steps']
        self.assertFalse(steps[0]['with']['persist-credentials'])
        self.assertEqual(steps[0]['with']['ref'], 'main')
        commands = [s for s in steps if 'run' in s]
        self.assertEqual(len(commands), 1)
        self.assertTrue(commands[0]['run'].endswith('ci:decision:packet-inspect'))
        for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'REGISTRY_TOKEN'):
            self.assertEqual(commands[0]['env'][key], '${{ github.token }}')
        self.assertNotIn('secrets.', path.read_text())
        self.assertNotIn('create-github-app-token', path.read_text())
        self.assertEqual(steps[-1]['if'], 'always()')
        self.assertEqual(steps[-1]['with']['retention-days'], 7)

    def environment(self, directory):
        return {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REPOSITORY': mod.REPOSITORY,
                'GITHUB_REF': 'refs/heads/main', 'GITHUB_ACTOR': 'reviewer',
                'GITHUB_WORKFLOW_REF': mod.REPOSITORY + '/.github/workflows/decision-packet-inspection.yml@refs/heads/main',
                'GITHUB_TOKEN': 'workflow-only', 'GH_TOKEN': 'workflow-only', 'REGISTRY_TOKEN': 'workflow-only',
                'PACKET_INSPECTION_REQUEST_HASH': mod.REQUEST_HASH, 'RUNNER_TEMP': directory}

    def test_native_entrypoint_retains_only_bounded_non_authorizing_receipt(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, self.environment(directory), clear=True), \
             mock.patch.object(mod, 'github_api', side_effect=self.api), \
             mock.patch.object(mod.packets, 'command', side_effect=self.command), \
             mock.patch.object(mod.packets, 'private_review_registry'), \
             mock.patch.object(mod.packets, 'metadata_reuse_enabled', return_value=False), redirect_stdout(io.StringIO()):
            mod.main()
            raw = (Path(directory) / 'maestro-packet-inspection-receipt.json').read_text()
            self.assertLess(len(raw), 16 * 1024)
            self.assertNotIn('workflow-only', raw)
            receipt = json.loads(raw)
            self.assertEqual(receipt['status'], 'verified-existing')
            self.assertFalse(receipt['authorization'])
            self.assertNotIn('DOCKER_CONFIG', os.environ)
            self.assertEqual(self.commands[0][:3], ['oras', 'login', 'ghcr.io'])
            # Fake command runner rejects every write or payload request. API
            # fake accepts only fixed metadata endpoints; production uses GET.
            self.assertEqual(len(self.commands), 5)

    def test_denial_404_and_timeout_remain_unresolved_without_reflecting_errors(self):
        for failure in (ValueError('denied secret'), ValueError('404 secret'),
                        subprocess.TimeoutExpired(['secret'], 1)):
            with tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, self.environment(directory), clear=True), \
                 mock.patch.object(mod, 'github_api', side_effect=self.api), \
                 mock.patch.object(mod.packets, 'command', return_value=b''), \
                 mock.patch.object(mod, 'inspect', side_effect=failure), \
                 self.assertRaisesRegex(ValueError, 'unresolved'):
                try: mod.main()
                finally:
                    receipt = (Path(directory) / 'maestro-packet-inspection-receipt.json').read_text()
                    self.assertNotIn('secret', receipt)
                    self.assertEqual(json.loads(receipt)['status'], 'unresolved')
                    self.assertFalse(json.loads(receipt)['authorization'])

    def test_direct_invocation_rejects_other_events_refs_workflow_credentials_or_unprotected_main(self):
        with tempfile.TemporaryDirectory() as directory:
            original = self.environment(directory)
            for key in ('GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_REPOSITORY', 'GITHUB_WORKFLOW_REF',
                        'GH_TOKEN', 'REGISTRY_TOKEN', 'GITHUB_TOKEN'):
                env = dict(original, **{key: 'wrong'})
                with mock.patch.dict(os.environ, env, clear=True), \
                     mock.patch.object(mod, 'github_api', side_effect=self.api), \
                     mock.patch.object(mod.packets, 'command') as command, self.assertRaises(ValueError):
                    mod.main()
                command.assert_not_called()
            self.responses[f'repos/{mod.REPOSITORY}/branches/main']['protected'] = False
            with mock.patch.dict(os.environ, original, clear=True), \
                 mock.patch.object(mod, 'github_api', side_effect=self.api), self.assertRaises(ValueError): mod.main()


class LoginSubprocess(unittest.TestCase):
    """Exercise the real bounded runner with a local fake executable, no network."""
    TOKEN = 'synthetic-inspector-stdin-fixture-only'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.receipt = self.directory / 'child.json'
        fake = self.directory / 'oras'
        fake.write_text('#!' + sys.executable + '\n' + r"""
import hashlib, json, os, resource, sys, time
assert sys.argv[1:] == ['login', 'ghcr.io', '--username', 'fixture-reviewer', '--password-stdin']
data = sys.stdin.buffer.read()
assert hashlib.sha256(data).hexdigest() == os.environ['FIXTURE_STDIN_SHA256']
with open(os.environ['FIXTURE_CHILD_RECEIPT'], 'w') as output:
    json.dump({'argv': sys.argv[1:], 'stdinSha256': hashlib.sha256(data).hexdigest(),
               'stdinBytes': len(data), 'fileLimit': list(resource.getrlimit(resource.RLIMIT_FSIZE))}, output)
mode = os.environ['FIXTURE_MODE']
if mode == 'failure':
    sys.stdout.buffer.write(data)
    sys.stderr.buffer.write(data + b' forbidden HTTP/1.1 403')
    sys.exit(1)
if mode == 'oversized':
    os.write(1, b'x' * (3 * 1024**2))
    sys.exit(1)
if mode == 'timeout':
    time.sleep(5)
print('Login Succeeded')
""")
        fake.chmod(0o700)
        self.environment = {'PATH': str(self.directory), 'GITHUB_ACTOR': 'fixture-reviewer',
            'FIXTURE_CHILD_RECEIPT': str(self.receipt), 'FIXTURE_MODE': 'success',
            'FIXTURE_STDIN_SHA256': hashlib.sha256(self.TOKEN.encode()).hexdigest()}

    def assert_stdin_only(self):
        receipt = json.loads(self.receipt.read_text())
        self.assertNotIn(self.TOKEN, self.receipt.read_text())
        self.assertEqual(receipt['stdinSha256'], self.environment['FIXTURE_STDIN_SHA256'])
        self.assertEqual(receipt['stdinBytes'], len(self.TOKEN))
        self.assertEqual(receipt['fileLimit'], [mod.packets.MAX_COMMAND_OUTPUT] * 2)
        self.assertEqual(receipt['argv'], ['login', 'ghcr.io', '--username', 'fixture-reviewer', '--password-stdin'])

    def test_real_runner_consumes_anonymous_stdin_without_logging_token(self):
        captured = io.StringIO()
        with mock.patch.dict(os.environ, self.environment, clear=True), redirect_stdout(captured):
            mod.registry_login(self.TOKEN)
        self.assertEqual(captured.getvalue(), '')
        self.assert_stdin_only()

    def test_real_failure_output_is_bounded_and_never_reflects_stdin(self):
        self.environment['FIXTURE_MODE'] = 'failure'
        captured = io.StringIO()
        with mock.patch.dict(os.environ, self.environment, clear=True), redirect_stdout(captured), \
             self.assertRaises(ValueError) as raised:
            mod.registry_login(self.TOKEN)
        self.assertNotIn(self.TOKEN, str(raised.exception) + captured.getvalue())
        self.assertIn('authorization-denied', str(raised.exception))
        self.assert_stdin_only()

    def test_real_runner_retains_output_file_bound(self):
        self.environment['FIXTURE_MODE'] = 'oversized'
        with mock.patch.dict(os.environ, self.environment, clear=True), self.assertRaises(ValueError):
            mod.registry_login(self.TOKEN)
        self.assert_stdin_only()

    def test_real_runner_honors_shorter_inherited_deadline(self):
        self.environment['FIXTURE_MODE'] = 'timeout'
        started = time.monotonic()
        with mock.patch.dict(os.environ, self.environment, clear=True), mod.operations.budget(.25), \
             self.assertRaises(ValueError) as raised:
            mod.registry_login(self.TOKEN)
        self.assertIn('timeout', str(raised.exception))
        self.assertLess(time.monotonic() - started, 3)
        self.assert_stdin_only()


if __name__ == '__main__':
    unittest.main()
