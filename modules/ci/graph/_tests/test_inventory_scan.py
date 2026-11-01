#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Consolidated phases retain real evidence checks without intermediate NAR I/O."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '_source'))
import transfer

WORKFLOW = Path(os.environ.get('MAESTRO_CI_WORKFLOW', ROOT / '.github/workflows/ci.yml'))
CACHE_SOURCE = Path(os.environ.get('MAESTRO_DISTRIBUTION_CACHE_SOURCE', ROOT / 'modules/ci/graph/_source/distribution-cache.py'))
CORE = Path(os.environ.get('MAESTRO_DECISION_CORE', ROOT / 'modules/ci/authority/_source/decisions'))
MEASUREMENT = Path(os.environ.get('MAESTRO_TEST_MEASUREMENT_SOURCE', ROOT / 'modules/ci/checks/_source/measure-phase.sh'))
SCANNER = Path(os.environ.get('MAESTRO_TEST_SCANNER_SOURCE', ROOT / 'modules/ci/security/_source/security-scan.sh'))
PRODUCER = dict(GITHUB_REPOSITORY='closure-labs/maestro', GITHUB_SHA='a' * 40,
                GITHUB_RUN_ID='7', GITHUB_RUN_ATTEMPT='2')
STORE = '/nix/store/' + 'a' * 32 + '-fixture'
NAR = 'sha256-' + 'A' * 43 + '='


class LocalInventory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'; self.bin.mkdir()
        self.evidence = self.root / 'evidence'; self.evidence.mkdir()
        for name in transfer.EVIDENCE_FILES:
            (self.evidence / name).write_text('original native evidence: ' + name)
        self.target = {'attribute': 'packages.x86_64-linux.fixture', 'derivation': 'fixture.drv', 'outputs': {'out': STORE}}
        self.graph = {'transport': {'inventory': [self.target]}}
        (self.root / 'graph.json').write_text(json.dumps(self.graph))
        (self.root / 'plan.json').write_text(json.dumps({'candidateRevision': PRODUCER['GITHUB_SHA'],
            'candidateGraphSha256': transfer.digest(self.graph)}))
        self.records = self.root / 'records.json'; self.records.write_text(json.dumps({STORE: {'narHash': NAR}}))
        self.calls = self.root / 'calls.jsonl'
        fake = self.bin / 'nix'
        fake.write_text('#!' + sys.executable + '\n' + '''
import json, os, sys
assert sys.argv[1:3] == ['path-info', '--json'], 'Unexpected build/export/restore command'
with open(os.environ['FIXTURE_NIX_CALLS'], 'a') as out: out.write(json.dumps(sys.argv[1:]) + '\\n')
print(open(os.environ['FIXTURE_NIX_RECORDS']).read())
''')
        fake.chmod(0o700)
        self.env = dict(PRODUCER, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
            SECURITY_INVENTORY=str(self.evidence), MAESTRO_DISTRIBUTION_CACHE_SOURCE=str(CACHE_SOURCE),
            MAESTRO_DECISION_CORE=str(CORE), FIXTURE_NIX_RECORDS=str(self.records), FIXTURE_NIX_CALLS=str(self.calls),
            GRAPH_PLAN_SHA256=hashlib.sha256((self.root / 'plan.json').read_bytes()).hexdigest())
        self.directory = self.root / 'inventory-binding'

    def invoke(self, action, **changes):
        args = ['transfer.py', action, 'inventory', str(self.directory), '--graph', str(self.root / 'graph.json'),
                '--plan', str(self.root / 'plan.json')]
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            with patch.dict(os.environ, dict(self.env, **changes)), patch.object(sys, 'argv', args), redirect_stdout(io.StringIO()):
                transfer.main()
        finally:
            os.chdir(previous)

    def bind(self):
        self.invoke('bind')
        self.env['TRANSFER_MANIFEST_SHA256'] = transfer.file_digest(self.directory / 'manifest.json')
        return json.loads((self.directory / 'manifest.json').read_text())

    def test_real_metadata_binding_and_verification_issue_no_copy_or_build(self):
        manifest = self.bind()
        self.assertIsNone(manifest['transport'])
        self.assertEqual(manifest['producer'], PRODUCER)
        self.assertEqual(manifest['roots'], [{'storePath': STORE, 'narHash': NAR}])
        self.assertEqual(manifest['targets'], [self.target])
        self.assertEqual(set(manifest['evidenceFiles']), set(transfer.EVIDENCE_FILES))
        self.invoke('verify')
        self.assertEqual(len(list(self.directory.iterdir())), 1)
        calls = [json.loads(x) for x in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(x == ['path-info', '--json', STORE] for x in calls))
        with self.assertRaisesRegex(ValueError, 'cannot restore'):
            self.invoke('restore')

    def test_downloaded_chunks_are_released_only_after_root_verification(self):
        incoming = self.root / 'appliance-transfer'; incoming.mkdir()
        chunk = incoming / 'distribution-cache.tar.part-000'; chunk.write_bytes(b'imported fixture')
        index = incoming / 'manifest.json'; index.write_text('retained index')
        retained = self.root / 'security-report'; retained.mkdir()
        final = retained / chunk.name; final.write_bytes(b'final retained fixture')
        self.records.write_text('{}')
        with self.assertRaises(ValueError): self.invoke('bind')
        self.assertTrue(chunk.exists())
        self.records.write_text(json.dumps({STORE: {'narHash': NAR}}))
        self.bind()
        self.assertFalse(chunk.exists())
        self.assertTrue(index.exists())
        self.assertTrue(final.exists())

    def test_staging_symlinks_cannot_delete_outside_chunks(self):
        outside = self.root / 'outside'; outside.mkdir()
        chunk = outside / 'distribution-cache.tar.part-000'; chunk.write_bytes(b'leave intact')
        (self.root / 'appliance-transfer').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Unsafe imported transport directory'): self.invoke('bind')
        self.assertTrue(chunk.exists())

    def test_each_native_document_swap_is_rejected(self):
        self.bind()
        for name in transfer.EVIDENCE_FILES:
            path = self.evidence / name; original = path.read_bytes(); path.write_bytes(b'forged')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'corrupt bound metadata'):
                self.invoke('verify')
            path.write_bytes(original)

    def test_manifest_attempt_graph_digest_and_nar_substitution_fail(self):
        self.bind()
        for change in ({'GITHUB_RUN_ATTEMPT': '3'}, {'TRANSFER_MANIFEST_SHA256': 'b' * 64},
                       {'GRAPH_PLAN_SHA256': 'b' * 64}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.invoke('verify', **change)
        for bad in ({}, {STORE: {'narHash': 'sha256-' + 'B' * 43 + '='}},
                    {STORE: {'narHash': NAR}, STORE + '-extra': {'narHash': NAR}}):
            self.records.write_text(json.dumps(bad))
            with self.subTest(records=bad), self.assertRaises(ValueError): self.invoke('verify')


class ConsolidatedWorkflow(unittest.TestCase):
    def test_one_inventory_scan_and_final_export_with_real_scan_outcome(self):
        jobs = json.loads(subprocess.check_output(['yq', '-o=json', '.jobs', str(WORKFLOW)], text=True))
        self.assertNotIn('scan', jobs)
        job = jobs['qualification']; steps = job['steps']
        commands = [x['run'].split()[-1] for x in steps if 'run' in x]
        for task in ('ci:inventory:assets', 'ci:inventory:bind', 'ci:inventory:verify', 'ci:security:scan', 'ci:decision:candidate'):
            self.assertEqual(commands.count(task), 1)
        self.assertLess(commands.index('ci:inventory:assets'), commands.index('ci:inventory:bind'))
        self.assertLess(commands.index('ci:inventory:verify'), commands.index('ci:security:scan'))
        self.assertLess(commands.index('ci:security:scan'), commands.index('ci:decision:candidate'))
        self.assertNotIn('maestro-inventory-transfer', WORKFLOW.read_text())
        self.assertEqual(job['permissions'], {'actions': 'read', 'attestations': 'read', 'contents': 'read'})
        scan = next(s for s in steps if s.get('id') == 'native_scan')
        self.assertNotIn('if', scan)
        self.assertNotIn('continue-on-error', scan)
        self.assertTrue(all(not s.get('continue-on-error', False) for s in steps))
        self.assertEqual(job['outputs']['scan_result'], '${{ steps.native_scan.conclusion }}')
        for name in ('security', 'signing', 'verdict'):
            self.assertNotIn('scan', jobs[name]['needs'])
        for name in ('security', 'signing'):
            self.assertIn("needs.qualification.outputs.scan_result == 'success'", jobs[name]['if'])
        self.assertIn('comparison', jobs['security']['needs'])
        self.assertIn('comparison', jobs['verdict']['needs'])
        diagnostic = next(s for s in steps if s.get('with', {}).get('name') == 'maestro-qualification-diagnostics')
        self.assertEqual(diagnostic['if'], 'always()')
        self.assertGreater(steps.index(diagnostic), steps.index(scan))

    def test_scanner_still_requires_independently_fresh_database_and_health(self):
        source = SCANNER.read_text()
        for setting in ('GRYPE_DB_AUTO_UPDATE=true', 'GRYPE_DB_REQUIRE_UPDATE_CHECK=true',
                        'GRYPE_DB_VALIDATE_AGE=true', 'GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h'):
            self.assertIn(setting, source)
        self.assertIn('GRYPE_DB_CACHE_DIR="$work/grype-db"', source)
        self.assertIn('scanner-check.cdx.json', source)
        self.assertIn('cargo-audit audit --file', source)

    def test_real_resource_prefix_records_failure_without_turning_it_into_success(self):
        self.resource_failure('exit 17', 17)

    def test_signal_termination_is_not_recorded_as_success_by_gnu_time(self):
        self.resource_failure('kill -KILL $$', 137)

    def resource_failure(self, command, expected):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); script = root / 'phase.sh'
            # GNU time re-executes this file; the Nix sandbox has no /usr/bin/env.
            bash = shutil.which('bash')
            self.assertIsNotNone(bash)
            script.write_text('#!' + bash + '\nset -euo pipefail\n' + MEASUREMENT.read_text() + '\n' + command + '\n')
            script.chmod(0o700)
            env = dict(os.environ, RUNNER_TEMP=directory, MAESTRO_CI_TIME=shutil.which('time'),
                       MAESTRO_CI_MEASURE_PHASE='scan')
            env.pop('MAESTRO_CI_MEASURED', None)
            result = subprocess.run([bash, str(script)], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, expected, result.stderr)
            report = root / 'maestro-qualification-diagnostics'
            value = json.loads((report / 'scan.resources.json').read_text())
            self.assertEqual(value['exitCode'], expected)
            self.assertGreater(value['maxChildRssKiB'], 0)
            self.assertTrue((report / 'scan.disk-before.txt').is_file())
            self.assertTrue((report / 'scan.disk-after.txt').is_file())


if __name__ == '__main__':
    unittest.main()
