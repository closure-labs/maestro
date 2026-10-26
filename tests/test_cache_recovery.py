# SPDX-License-Identifier: Apache-2.0
"""Exact admitted cache recovery selects data without widening publication."""
from contextlib import redirect_stdout
from collections import Counter
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
AUTOMATION = ROOT / 'modules/ci/authority/_source'
sys.path.insert(0, str(AUTOMATION / 'decisions'))


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), AUTOMATION / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


download = load('decision-download')
retained = load('decision-retained')


class RecoveryDownload(unittest.TestCase):
    def selector(self, **overrides):
        return dict(CANDIDATE_PROPOSAL_HASH='a' * 64, CANDIDATE_RUN='',
                    PUBLICATION_METADATA_ONLY='true', CANDIDATE_RELEASE_ONLY='true', **overrides)

    def invoke(self, environment):
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(download, 'api', side_effect=AssertionError('Actions API reached')) as api, \
                patch.object(download.operations, 'run', side_effect=AssertionError('transport reached')) as transport:
            try:
                download.main()
            finally:
                api.assert_not_called()
                transport.assert_not_called()

    def test_canonical_metadata_selector_bypasses_actions_before_any_transport(self):
        with self.assertRaises(SystemExit) as caught:
            self.invoke(self.selector())
        self.assertEqual(caught.exception.code, 3)

    def test_invalid_or_conflicting_selector_never_falls_back_to_actions(self):
        cases = [{'CANDIDATE_PROPOSAL_HASH': value} for value in
                 ('a' * 63, 'a' * 65, 'A' * 64, 'a' * 64 + '\n', '../proposal', '--optional')]
        cases += [{'CANDIDATE_RUN': value} for value in ('0', '-1', '01', '123\n', 'a', '1' * 21)]
        cases += [{'PUBLICATION_METADATA_ONLY': 'false'},
                  {'PUBLICATION_METADATA_ONLY': ''}, {'CANDIDATE_RELEASE_ONLY': 'false'},
                  {'CANDIDATE_RELEASE_ONLY': ''}]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.invoke(dict(self.selector(), **changes))

    def test_existing_explicit_candidate_route_still_reaches_actions(self):
        class ActionsRead(Exception):
            pass
        with patch.dict(os.environ, {'CANDIDATE_RUN': '123', 'PUBLICATION_METADATA_ONLY': 'true'}, clear=True), \
                patch.object(download, 'api', side_effect=ActionsRead) as api:
            with self.assertRaises(ActionsRead):
                download.main()
        api.assert_called_once_with('actions/runs/123')

    def test_shell_routes_exact_selector_to_admitted_retained_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            binary = folder / 'bin'
            binary.mkdir()
            calls = folder / 'calls.jsonl'
            oras = binary / 'oras'
            oras.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                            'sys.stdin.read()\n'
                            'with open(os.environ["RECOVERY_CALLS"],"a") as f:'
                            'f.write(json.dumps(["oras",*sys.argv[1:]])+"\\n")\n')
            oras.chmod(0o700)
            reader = folder / 'retained.py'
            reader.write_text('import json,os,sys\nfrom pathlib import Path\n'
                              'value={"args":sys.argv[1:],"metadata":os.environ["PUBLICATION_METADATA_ONLY"],'
                              '"registry":os.environ["DOCKER_CONFIG"],'
                              '"registryExists":Path(os.environ["DOCKER_CONFIG"]).is_dir(),'
                              '"deadline":float(os.environ["CI_OPERATION_DEADLINE"])}\n'
                              'Path(os.environ["RECOVERY_RESULT"]).write_text(json.dumps(value))\n')
            result_path = folder / 'result.json'
            env = dict(self.selector(), PATH=str(binary) + os.pathsep + os.environ['PATH'],
                       GH_TOKEN='fixture-secret', GITHUB_ACTOR='fixture',
                       RUNNER_TEMP=str(folder), MAESTRO_SYSTEM_ROOT=str(ROOT),
                       MAESTRO_OPERATIONS_SOURCE=str(AUTOMATION / 'decisions/operations.py'),
                       MAESTRO_DECISION_DOWNLOAD_SOURCE=str(AUTOMATION / 'decision-download.py'),
                       MAESTRO_DECISION_RETAINED_SOURCE=str(reader),
                       DECISION_DIRECTORY=str(folder / 'evidence'),
                       RECOVERY_CALLS=str(calls), RECOVERY_RESULT=str(result_path))
            result = subprocess.run(['bash', str(AUTOMATION / 'decision-download.sh')], env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result_path.read_text())
            self.assertEqual(value['args'], ['--config', str(ROOT / 'modules/ci/authority/_source/decision-policy.json'),
                '--directory', str(folder / 'evidence'), '--release-only', '--proposal-hash', 'a' * 64,
                '--admitted-release'])
            self.assertEqual(value['metadata'], 'true')
            self.assertGreater(value['deadline'] - time.monotonic(), 0)
            self.assertLessEqual(value['deadline'] - time.monotonic(), 900)
            self.assertTrue(value['registryExists'])
            self.assertFalse(Path(value['registry']).exists(), 'temporary registry credentials survived')
            self.assertEqual(len(calls.read_text().splitlines()), 1)
            self.assertNotIn('fixture-secret', calls.read_text() + result.stdout + result.stderr)


class AdmittedRelease(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.producer = {'repository': 'closure-labs/maestro', 'revision': 'a' * 40,
                         'sourceRevision': 'a' * 40, 'workflow': '.github/workflows/release-candidate.yml',
                         'runId': 123, 'runAttempt': 1}
        self.product = {'revision': 'a' * 40,
                        'assets': {'maestro-v1.2.3.iso.sha256': 'b' * 64}}
        self.proposal = {'kind': 'release-product', 'payload': {'disposition': 'accepted',
            'rationale': 'Exact fixture bytes reviewed', 'supersedes': [], 'product': self.product,
            'packet': {'reference': retained.packets.REGISTRY + '@sha256:' + 'c' * 64,
                       'sha256': 'd' * 64, 'producer': self.producer}}}
        self.digest = retained.canonical_hash(self.proposal)

    def invoke(self, records, *, pending=None, release_only=True, metadata=True, requested=None):
        argv = ['retained', '--config', str(ROOT / 'modules/ci/authority/_source/decision-policy.json'),
                '--directory', str(self.folder / 'evidence'), '--admitted-release',
                '--proposal-hash', self.digest if requested is None else requested]
        if release_only:
            argv.append('--release-only')
        environment = {'PUBLICATION_METADATA_ONLY': 'true' if metadata else 'false',
                       'GITHUB_OUTPUT': str(self.folder / 'output')}
        manifest = {'producer': self.producer,
                    'files': {name: {'sha256': digest} for name, digest in self.product['assets'].items()}}
        native_producer = {k: v for k, v in self.producer.items() if k not in ('repository', 'sourceRevision')}
        scan = {'revision': self.product['revision'], 'producer': native_producer, 'profiles': {'maestro': {}}}
        with patch.dict(os.environ, environment, clear=True), patch.object(sys, 'argv', argv), \
                patch.object(retained.common, 'config', return_value={'repository': 'closure-labs/maestro'}), \
                patch.object(retained.common, 'ledger', return_value=('e' * 40, records)), \
                patch.object(retained.common, 'historical_provenance'), \
                patch.object(retained, 'pending', return_value=pending or {}) as pending_read, \
                patch.object(retained.authority, 'collection', return_value=[{'draft': False, 'tag_name': 'v1.2.3'}]) as releases_read, \
                patch.object(retained.packets, 'metadata', return_value=manifest) as descriptor, \
                patch.object(retained.packets, 'metadata_bytes', return_value=b'{}') as metadata_read, \
                patch.object(retained.packets, 'fetch', side_effect=AssertionError('bulk packet fetched')), \
                patch.object(retained.common, 'scans', return_value=scan), \
                patch.object(retained.common, 'product', return_value=self.product), \
                patch.object(retained, 'verify_native_files'), redirect_stdout(io.StringIO()) as output:
            try:
                retained.main()
            except ValueError:
                descriptor.assert_not_called()
                metadata_read.assert_not_called()
                pending_read.assert_not_called()
                raise
        self.assertEqual(descriptor.call_args.args[2], 'decision-packet.json')
        pending_read.assert_not_called()
        releases_read.assert_not_called()
        self.assertEqual({call.args[2] for call in metadata_read.call_args_list},
                         {'scans.json', 'product.json', 'inputs.sha256',
                          'inventory/maestro-system.cdx.json', 'inventory/xen-orchestra-supply.cdx.json',
                          'inventory/Cargo.lock'})
        return json.loads(output.getvalue())

    def test_exact_current_accepted_record_recovers_even_if_release_is_published(self):
        self.assertEqual(retained.current_published_products({}, {self.digest: self.proposal},
                                                           {'v1.2.3'}, self.digest), set())
        value = self.invoke({self.digest: self.proposal})
        self.assertEqual(value['proposal_hash'], self.digest)
        self.assertEqual(value['release_tag'], 'v1.2.3')
        self.assertEqual(value['retained'], 'true')
        self.assertIn('release_tag=v1.2.3\n', (self.folder / 'output').read_text())

    def test_pending_nonofficial_rejected_or_revoked_proposals_are_ineligible(self):
        with self.assertRaises(ValueError):
            self.invoke({}, pending={self.digest: self.proposal})
        for kind, disposition in [('security-findings', 'accepted'), ('release-product', 'rejected'),
                                  ('release-product', 'revoked')]:
            proposal = deepcopy(self.proposal)
            proposal['kind'] = kind
            proposal['payload']['disposition'] = disposition
            with self.subTest(kind=kind, disposition=disposition), self.assertRaises(ValueError):
                self.invoke({self.digest: proposal})

    def test_superseded_record_cannot_recover_through_another_current_approval(self):
        newer = deepcopy(self.proposal)
        newer['payload']['supersedes'] = [self.digest]
        newer['payload']['rationale'] = 'Superseding review'
        digest = retained.canonical_hash(newer)
        with self.assertRaises(ValueError):
            self.invoke({self.digest: self.proposal, digest: newer})

    def test_admitted_cli_requires_release_metadata_and_canonical_exact_hash(self):
        for options in ({'release_only': False}, {'metadata': False}, {'requested': 'A' * 64},
                        {'requested': 'a' * 63}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.invoke({self.digest: self.proposal}, **options)


class FreshRecovery(unittest.TestCase):
    def setUp(self):
        AdmittedRelease.setUp(self)
        self.product['repository'] = download.REPOSITORY
        self.digest = retained.canonical_hash(self.proposal)
        self.run = {'id': 456, 'run_attempt': 1, 'repository': {'full_name': download.REPOSITORY},
                    'head_branch': 'main', 'event': 'workflow_dispatch', 'status': 'completed',
                    'conclusion': 'success', 'path': '.github/workflows/security.yml',
                    'head_sha': 'f' * 40}
        self.scans = {'repository': download.REPOSITORY, 'revision': self.product['revision'],
                      'producer': {'revision': self.run['head_sha'], 'workflow': self.run['path'],
                                   'runId': self.run['id'], 'runAttempt': self.run['run_attempt']}}
        self.archive = b'authenticated fixture archive'
        self.artifact = {'id': 789, 'name': 'maestro-release-product', 'expired': False,
                         'digest': 'sha256:' + hashlib.sha256(self.archive).hexdigest()}

    def invoke(self, *, records=None, run=None, artifacts=None, product=None, scans=None,
               corrupt_archive=False, environment=None):
        shutil.rmtree(self.folder / 'evidence', ignore_errors=True)
        (self.folder / 'output').unlink(missing_ok=True)
        env = dict(CANDIDATE_PROPOSAL_HASH=self.digest, CANDIDATE_RUN='456',
                   CANDIDATE_RELEASE_ONLY='true', PUBLICATION_METADATA_ONLY='true',
                   CANDIDATE_WORKFLOW='.github/workflows/security.yml', MAESTRO_SYSTEM_ROOT=str(ROOT),
                   DECISION_DIRECTORY=str(self.folder / 'evidence'), GITHUB_OUTPUT=str(self.folder / 'output'))
        env.update(environment or {})
        selected_run = self.run if run is None else run
        selected_artifacts = [self.artifact] if artifacts is None else artifacts
        selected_product = self.product if product is None else product
        selected_scans = self.scans if scans is None else scans
        self.api_calls = []
        self.bulk_calls = []
        self.extract_calls = []

        def api(endpoint):
            self.assertEqual(selection.call_count, 1, 'Actions reached before protected admission selection')
            self.api_calls.append(endpoint)
            if endpoint == 'actions/runs/456':
                return deepcopy(selected_run)
            self.assertEqual(endpoint, 'actions/runs/456/artifacts?per_page=100')
            return {'total_count': len(selected_artifacts), 'artifacts': deepcopy(selected_artifacts)}

        def bulk(args, **kwargs):
            self.bulk_calls.append(args)
            self.assertEqual(args, ['gh', 'api', 'repos/closure-labs/maestro/actions/artifacts/789/zip'])
            self.assertEqual(kwargs['timeout'], 900)
            self.assertTrue(kwargs['check'])
            kwargs['stdout'].write(b'corrupt archive' if corrupt_archive else self.archive)

        def extract(archive, output):
            self.assertEqual(archive.read(), self.archive)
            self.extract_calls.append(output)
            (output / 'scans.json').write_text(json.dumps(selected_scans))
            (output / 'product.json').write_text(json.dumps(selected_product))

        with patch.dict(os.environ, env, clear=True), \
                patch.object(download.common, 'config', return_value={'repository': download.REPOSITORY}) as config, \
                patch.object(download.common, 'ledger', return_value=('e' * 40,
                    {self.digest: self.proposal} if records is None else records)), \
                patch.object(download.common, 'historical_provenance'), \
                patch.object(download.common, 'admitted_release', wraps=download.common.admitted_release) as selection, \
                patch.object(download, 'api', side_effect=api), \
                patch.object(download.operations, 'run', side_effect=bulk), \
                patch.object(download, 'extract', side_effect=extract), redirect_stdout(io.StringIO()) as stdout:
            download.main()
        config.assert_called_once_with(ROOT / 'modules/ci/authority/_source/decision-policy.json', live=True)
        return json.loads(stdout.getvalue())

    def assert_blocked(self, **options):
        with self.assertRaises(ValueError):
            self.invoke(**options)
        self.assertFalse((self.folder / 'output').exists(), 'rejected recovery emitted usable outputs')

    def test_fresh_security_evidence_keeps_exact_admitted_product_and_source(self):
        value = self.invoke()
        self.assertEqual(value['source_sha'], self.product['revision'])
        self.assertNotEqual(value['source_sha'], self.run['head_sha'])
        self.assertEqual(value['candidate_run'], '456')
        self.assertEqual(value['release_tag'], 'v1.2.3')
        self.assertEqual(len(self.bulk_calls), 1)
        self.assertEqual(len(self.extract_calls), 1)
        self.assertEqual(json.loads(Path(value['product']).read_text()), self.proposal['payload']['product'])

    def test_decision_workflow_selects_official_observations_for_risk_review(self):
        workflow = json.loads(subprocess.check_output(
            ['yq', '-o=json', '.', str(ROOT / '.github/workflows/decisions.yml')], text=True))
        selector = workflow['on']['workflow_dispatch']['inputs']['proposal_hash']
        self.assertEqual(selector['type'], 'string')
        self.assertEqual(selector['default'], '')
        job = workflow['jobs']['reconcile']
        self.assertIn("github.ref == 'refs/heads/main'", job['if'])
        checkout = next(step for step in job['steps']
                        if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'], 'main')
        self.assertFalse(checkout['with']['persist-credentials'])
        candidate = next(step for step in job['steps'] if step.get('id') == 'candidate')
        self.assertTrue(candidate['run'].endswith(' ci:decision:download'))
        expected = {
            'CANDIDATE_RUN': "${{ inputs.candidate_run || '' }}",
            'CANDIDATE_PROPOSAL_HASH': "${{ inputs.proposal_hash || '' }}",
            'PUBLICATION_METADATA_ONLY': "${{ inputs.proposal_hash != '' && 'true' || 'false' }}",
            'CANDIDATE_RELEASE_ONLY': "${{ inputs.proposal_hash != '' && 'true' || 'false' }}",
            'CANDIDATE_WORKFLOW': "${{ inputs.proposal_hash != '' && '.github/workflows/security.yml' || '' }}",
        }
        self.assertEqual({key: candidate['env'].get(key) for key in expected}, expected)
        # Exercise the actual downloader with the explicit workflow inputs. The
        # fixture API rejects any weekly artifact lookup or unadmitted selection.
        value = self.invoke(environment={
            'CANDIDATE_RUN': '456', 'CANDIDATE_PROPOSAL_HASH': self.digest,
            'PUBLICATION_METADATA_ONLY': 'true', 'CANDIDATE_RELEASE_ONLY': 'true',
            'CANDIDATE_WORKFLOW': '.github/workflows/security.yml'})
        self.assertEqual(value['candidate_run'], '456')
        self.assertEqual(value['release'], 'true')
        self.assertEqual(json.loads(Path(value['product']).read_text()), self.proposal['payload']['product'])
        review = next(step for step in job['steps']
                      if step.get('env', {}).get('DECISION_KIND') == 'security-findings')
        self.assertTrue(review['run'].endswith(' ci:decision:reconcile'))
        self.assertEqual(workflow['concurrency']['cancel-in-progress'], False)

    def test_pending_revoked_superseded_and_nonofficial_selection_block_before_actions(self):
        newer = deepcopy(self.proposal)
        newer['payload'].update(supersedes=[self.digest], rationale='Superseding exact review')
        rejected = deepcopy(self.proposal)
        rejected['payload']['disposition'] = 'rejected'
        revoked = deepcopy(self.proposal)
        revoked['payload']['disposition'] = 'revoked'
        wrong_kind = deepcopy(self.proposal)
        wrong_kind['kind'] = 'security-findings'
        for records in ({}, {self.digest: rejected}, {self.digest: revoked}, {self.digest: wrong_kind},
                        {self.digest: self.proposal, retained.canonical_hash(newer): newer}):
            with self.subTest(records=list(records)):
                self.assert_blocked(records=records)
                self.assertEqual(self.api_calls, [])
                self.assertEqual(self.bulk_calls, [])

    def test_different_product_and_wrong_archive_hash_never_emit_recovery_outputs(self):
        changed = deepcopy(self.product)
        changed['assets']['maestro-v1.2.3.iso.sha256'] = '0' * 64
        self.assert_blocked(product=changed)
        self.assertEqual(len(self.bulk_calls), 1)
        self.assert_blocked(corrupt_archive=True)
        self.assertEqual(self.extract_calls, [])

    def test_missing_expired_duplicate_or_wrong_artifact_never_falls_back_to_retained(self):
        expired = dict(self.artifact, expired=True)
        wrong = dict(self.artifact, name='maestro-weekly-security-report')
        for artifacts in ([], [expired], [self.artifact, self.artifact], [wrong]):
            with self.subTest(artifacts=artifacts):
                self.assert_blocked(artifacts=artifacts)
                self.assertEqual(self.bulk_calls, [])

    def test_wrong_run_identity_attempt_or_workflow_blocks_before_bulk(self):
        for key, value in (('id', 457), ('id', True), ('run_attempt', True), ('run_attempt', 0),
                           ('run_attempt', '1'),
                           ('path', '.github/workflows/ci.yml'), ('path', '.github/workflows/release.yml'),
                           ('head_branch', 'candidate'), ('conclusion', 'failure')):
            with self.subTest(key=key, value=value):
                self.assert_blocked(run=dict(self.run, **{key: value}))
                self.assertEqual(self.bulk_calls, [])
        self.assert_blocked(environment={'CANDIDATE_WORKFLOW': '.github/workflows/ci.yml'})
        self.assertEqual(self.api_calls, [])

    def test_changed_fresh_document_producer_is_rejected(self):
        for key, value in (('revision', '0' * 40), ('workflow', '.github/workflows/ci.yml'),
                           ('runId', 457), ('runAttempt', 2), ('runAttempt', True)):
            scans = deepcopy(self.scans)
            scans['producer'][key] = value
            with self.subTest(key=key, value=value):
                self.assert_blocked(scans=scans)


class RecoveryWorkflow(unittest.TestCase):
    def test_native_workflow_guard_limits_task_output_option(self):
        policy = (ROOT / 'modules/ci/checks/contracts.nix').read_text()
        pattern = re.search(r'grep -Ev "([^"\n]+)"; then', policy).group(1)
        prefix = "nix run --accept-flake-config .#devenv -- tasks run --mode single "
        options = "--option 'packages:pkgs!' '' "
        for task in ('ci:decision:download', 'ci:decision:publication', 'release:inspect', 'ci:publish', 'release:journal', 'release:assets'):
            self.assertRegex(prefix + '--show-output ' + options + task, pattern)
        for command in (prefix + '--show-output ' + options + 'ci:decision:handoff',
                        prefix + '--show-output --trace-to stdout ' + options + 'ci:publish',
                        prefix + '--show-output ' + options + 'ci:publish; echo bypass',
                        prefix + '--show-output ' + options + 'ci:publish --extra',
                        prefix + '--show-output ' + "--option 'packages:pkgs!' curl ci:publish",
                        'bash modules/ci/authority/_source/publish.sh'):
            with self.subTest(command=command):
                self.assertNotRegex(command, pattern)

    def test_cache_only_routing_and_protected_native_execution_contract(self):
        workflow = json.loads(subprocess.check_output(
            ['yq', '-o=json', '.', str(ROOT / '.github/workflows/publication.yml')], text=True))
        self.assertEqual(workflow['name'], 'Publish admitted Maestro candidate')
        selector = workflow['on']['workflow_dispatch']['inputs']['proposal_hash']
        self.assertEqual(selector['type'], 'string')
        self.assertEqual(selector['default'], '')
        self.assertEqual(workflow['concurrency'], {'group': 'maestro-publication', 'queue': 'max',
                                                  'cancel-in-progress': False})
        job = workflow['jobs']['publish']
        self.assertIn("github.repository == 'closure-labs/maestro'", job['if'])
        self.assertIn("github.ref == 'refs/heads/main'", job['if'])
        self.assertEqual(job['environment'], 'publication')
        self.assertEqual(job['permissions'], {'actions': 'read', 'packages': 'read', 'attestations': 'read',
                                             'contents': 'read'})
        self.assertEqual(job['env']['PUBLICATION_PURPOSE'],
                         "${{ inputs.proposal_hash != '' && 'release' || 'rolling' }}")
        steps = job['steps']
        checkout = next(step for step in steps if step.get('uses', '').startswith('actions/checkout@'))
        self.assertRegex(checkout['uses'], r'^actions/checkout@[0-9a-f]{40}$')
        self.assertEqual(checkout['with'], {'ref': 'main', 'fetch-depth': 0, 'persist-credentials': False})
        candidate = next(step for step in steps if step.get('id') == 'candidate')
        self.assertEqual(candidate['env']['PUBLICATION_METADATA_ONLY'], 'true')
        self.assertEqual(candidate['env']['CANDIDATE_PROPOSAL_HASH'], "${{ inputs.proposal_hash || '' }}")
        self.assertEqual(candidate['env']['CANDIDATE_RELEASE_ONLY'],
                         "${{ inputs.proposal_hash != '' && 'true' || 'false' }}")
        self.assertEqual(candidate['env']['CANDIDATE_WORKFLOW'],
                         "${{ inputs.proposal_hash != '' && '.github/workflows/security.yml' || '.github/workflows/ci.yml' }}")
        reservation_index = next(i for i, step in enumerate(steps)
                                 if step.get('env', {}).get('PUBLICATION_STEP') == 'cache'
                                 and step['env'].get('PUBLICATION_STATE') == 'pending')
        reservation = steps[reservation_index]
        self.assertEqual(reservation['if'], "inputs.proposal_hash != ''")
        self.assertEqual(reservation['env']['PUBLICATION_KEY'], "${{ steps.candidate.outputs.release_tag }}")
        gate_index = next(i for i, step in enumerate(steps)
                          if step.get('run', '').endswith(' ci:decision:publication'))
        publish_index = next(i for i, step in enumerate(steps)
                             if step.get('run', '').endswith(' ci:publish'))
        self.assertLess(gate_index, reservation_index)
        self.assertLess(reservation_index, publish_index)
        journal_index = next(i for i, step in enumerate(steps)
                             if step.get('env', {}).get('PUBLICATION_STEP') == 'cache'
                             and step['env'].get('PUBLICATION_STATE') == 'complete')
        self.assertEqual(steps[journal_index]['env']['PUBLICATION_KEY'],
                         "${{ inputs.proposal_hash != '' && steps.candidate.outputs.release_tag || '' }}")
        self.assertEqual(steps[journal_index]['env']['PUBLICATION_STATE'], 'complete')
        following = steps[journal_index + 1:]
        observations = next(step for step in following if step.get('name') == 'Retain immutable decision byte reuse observations')
        self.assertEqual(observations['name'], 'Retain immutable decision byte reuse observations')
        self.assertEqual(observations['if'], 'always()')
        self.assertEqual(observations['uses'],
                         'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9')
        self.assertEqual(observations['with'], {
            'name': 'maestro-decision-byte-reuse-${{ github.job }}',
            'path': '${{ runner.temp }}/decision-git-blobs/*/observations.jsonl',
            'if-no-files-found': 'ignore', 'retention-days': 30})
        self.assertFalse(any('flakehub' in json.dumps(step).lower() for step in following))
        shown = Counter(step['run'].rsplit(' ', 1)[-1] for step in steps
                        if '--show-output' in step.get('run', ''))
        self.assertEqual(shown, Counter({'ci:decision:download': 1, 'release:inspect': 1,
                                        'ci:publish': 1, 'release:journal': 2, 'ci:decision:publication': 1}))
        for step in steps:
            self.assertNotIn('PUBLICATION_PURPOSE', step.get('env', {}), 'step overrides the selected purpose')
            if 'run' in step:
                self.assertRegex(step['run'], r"^nix run --accept-flake-config \.#devenv -- tasks run --mode single (?:--show-output )?--option 'packages:pkgs!' '' [a-z][a-z:-]+$")


if __name__ == '__main__':
    unittest.main()
