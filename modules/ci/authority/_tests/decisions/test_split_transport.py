# SPDX-License-Identifier: Apache-2.0
"""Split artifacts preserve exact producer and closure integrity without Nix builds."""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
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
import zipfile

ROOT = Path(__file__).resolve().parents[5]
SOURCE = ROOT / 'modules/ci/authority/_source'
sys.path.insert(0, str(SOURCE / 'decisions'))
spec = importlib.util.spec_from_file_location('split_download', SOURCE / 'decision-download.py')
download = importlib.util.module_from_spec(spec)
spec.loader.exec_module(download)
PART = 'distribution-cache.tar.part-000'


def archive(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as output:
        for name, value in files.items():
            output.writestr(name, value)
    return buffer.getvalue()


class SplitTransport(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'evidence'
        self.payload = b'fixture immutable compressed distribution\n' * 4096
        self.manifest = {'schema': 1, 'parts': {PART: {
            'sha256': hashlib.sha256(self.payload).hexdigest(), 'size': len(self.payload)}},
            'archiveSha256': hashlib.sha256(self.payload).hexdigest(), 'archiveSize': len(self.payload)}
        self.run = dict(id=123, run_attempt=2, head_sha='a' * 40, head_branch='main',
                        path='.github/workflows/ci.yml', event='push', status='completed', conclusion='success',
                        repository={'full_name': download.REPOSITORY})
        self.scans = dict(repository=download.REPOSITORY, revision='a' * 40,
                          producer=dict(workflow=self.run['path'], runId=123, runAttempt=2),
                          transport=self.manifest)
        self.product = dict(repository=download.REPOSITORY, revision='a' * 40, assets={})
        self.calls = []
        self.env = dict(CANDIDATE_RUN='123', CANDIDATE_REQUIRED='true',
                        CANDIDATE_WORKFLOW='.github/workflows/ci.yml', DECISION_DIRECTORY=str(self.output))

    def invoke(self, *, scans=None, product=None, payload=None, legacy=False,
               companions=1, expired=False, bad_digest=False, extra=None, run=None):
        documents = {'scans.json': json.dumps(self.scans if scans is None else scans),
                     'product.json': json.dumps(self.product if product is None else product),
                     'security-result.json': '{"status":"complete"}'}
        if legacy:
            documents[PART] = self.payload if payload is None else payload
        primary = archive(documents)
        members = {PART: self.payload if payload is None else payload}
        members.update(extra or {})
        companion = archive(members)
        artifacts = [dict(id=1, name='maestro-security-report', expired=False,
                          digest='sha256:' + hashlib.sha256(primary).hexdigest())]
        artifacts += [dict(id=i + 2, name='maestro-distribution-transport', expired=expired,
                           digest='sha256:' + ('f' * 64 if bad_digest else hashlib.sha256(companion).hexdigest()))
                      for i in range(companions)]

        def api(endpoint):
            if endpoint == 'actions/runs/123':
                return self.run if run is None else run
            self.assertEqual(endpoint, 'actions/runs/123/artifacts?per_page=100')
            return {'total_count': len(artifacts), 'artifacts': artifacts}

        def bulk(args, **kwargs):
            self.calls.append(args[-1])
            kwargs['stdout'].write(primary if args[-1].endswith('/1/zip') else companion)

        with patch.dict(os.environ, self.env, clear=True), patch.object(download, 'api', side_effect=api), \
                patch.object(download.operations, 'run', side_effect=bulk), redirect_stdout(io.StringIO()) as output:
            download.main()
        return json.loads(output.getvalue())

    def test_split_rejoins_exact_parts_and_preserves_attested_documents(self):
        result = self.invoke()
        self.assertEqual(result['candidate_run'], '123')
        self.assertEqual(json.loads((self.output / 'scans.json').read_text()), self.scans)
        self.assertEqual(json.loads((self.output / 'product.json').read_text()), self.product)
        self.assertEqual((self.output / PART).read_bytes(), self.payload)
        self.assertEqual(len(self.calls), 2)

    def test_companion_staging_uses_the_evidence_filesystem(self):
        with patch.object(download.tempfile, 'TemporaryDirectory', wraps=tempfile.TemporaryDirectory) as stage:
            self.invoke()
        stage.assert_called_once_with(dir=self.output)

    def test_legacy_bundle_never_fetches_a_companion(self):
        self.invoke(legacy=True, companions=0)
        self.assertEqual(len(self.calls), 1)

    def test_missing_ambiguous_or_expired_companion_fails_closed(self):
        for options in ({'companions': 0}, {'companions': 2}, {'expired': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.invoke(**options)
            if self.output.exists():
                import shutil
                shutil.rmtree(self.output)

    def test_wrong_archive_digest_or_swapped_payload_never_merges_parts(self):
        for options in ({'bad_digest': True}, {'payload': b'x' + self.payload[1:]},
                        {'extra': {'scans.json': '{}'}}, {'extra': {'../escape': 'bad'}}):
            with self.subTest(options=options.keys()), self.assertRaises(ValueError):
                self.invoke(**options)
            self.assertFalse((self.output / PART).exists())
            import shutil
            shutil.rmtree(self.output)

    def test_corrupt_legacy_payload_never_falls_back_to_companion(self):
        with self.assertRaises(ValueError):
            self.invoke(legacy=True, payload=b'bad')
        self.assertEqual(len(self.calls), 1)

    def test_required_run_cannot_discover_or_fall_back(self):
        self.env['CANDIDATE_RUN'] = ''
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(download, 'api', side_effect=AssertionError('discovery reached')), \
                self.assertRaisesRegex(ValueError, 'Exact candidate run ID required'):
            download.main()

    def test_missing_part_and_manifest_tampering_never_emit_usable_evidence(self):
        for field, value in (('archiveSize', self.manifest['archiveSize'] + 1),
                             ('schema', 2), ('parts', {})):
            scans = deepcopy(self.scans)
            scans['transport'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.invoke(scans=scans)
            self.assertFalse((self.output / PART).exists())
            import shutil
            shutil.rmtree(self.output)
        scans = deepcopy(self.scans)
        scans['transport']['parts']['distribution-cache.tar.part-001'] = scans['transport']['parts'][PART]
        with self.assertRaises(ValueError):
            self.invoke(scans=scans)
        self.assertFalse((self.output / PART).exists())

    def test_wrong_source_attempt_run_or_workflow_rejected_before_companion(self):
        mutations = [dict(revision='b' * 40), dict(repository='other/repo')]
        mutations += [dict(producer=dict(self.scans['producer'], **fields)) for fields in
                      ({'runAttempt': 1}, {'runId': 124}, {'workflow': '.github/workflows/security.yml'})]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.invoke(scans=dict(self.scans, **change))
            self.assertEqual(len(self.calls), 1)
            self.calls.clear()
            import shutil
            shutil.rmtree(self.output)

    def test_untrusted_producer_never_downloads_any_artifact(self):
        for change in ({'head_branch': 'candidate'}, {'event': 'pull_request'},
                       {'conclusion': 'failure'}, {'status': 'in_progress'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.invoke(run=dict(self.run, **change))
            self.assertEqual(self.calls, [])
            self.assertFalse(self.output.exists())

    def test_split_preserves_manifest_bytes_and_reduces_metadata_request_bytes(self):
        self.invoke()
        files = {p.name: p.read_bytes() for p in self.output.iterdir()}
        bundled = archive(files)
        metadata = archive({k: v for k, v in files.items() if k != PART})
        transport = archive({PART: files[PART]})
        self.assertLess(len(metadata), len(bundled) // 100)
        self.assertEqual(json.loads(files['scans.json'])['transport'], self.manifest)
        print(json.dumps({'fixtureBundledBytes': len(bundled), 'fixtureEvidenceBytes': len(metadata),
                          'fixtureTransportBytes': len(transport), 'evidenceRequestsBefore': 1,
                          'evidenceRequestsAfter': 1, 'restoreRequestsBefore': 1, 'restoreRequestsAfter': 2}))

    def test_workflow_split_and_consumers_keep_native_boundaries(self):
        def workflow(name):
            return json.loads(subprocess.check_output(['yq', '-o=json', '.',
                              str(ROOT / '.github/workflows' / name)], text=True))
        ci = workflow('ci.yml')['jobs']
        report = next(s for s in ci['scan']['steps'] if s.get('with', {}).get('name') == 'maestro-security-report')
        self.assertIn('!security-report/distribution-cache.tar.part-*', report['with']['path'])
        companion = next(s for s in ci['scan']['steps'] if s.get('with', {}).get('name') == 'maestro-distribution-transport')
        self.assertEqual(companion['with']['path'], 'security-report/distribution-cache.tar.part-*')
        self.assertIn("github.ref == 'refs/heads/main'", companion['if'])
        self.assertEqual(companion['with']['if-no-files-found'], 'error')
        self.assertEqual(companion['with']['retention-days'], report['with']['retention-days'])
        for job in ('security', 'signing'):
            downloads = [s['with']['name'] for s in ci[job]['steps']
                         if s.get('uses', '').startswith('actions/download-artifact@')]
            self.assertIn('maestro-security-report', downloads)
            self.assertNotIn('maestro-distribution-transport', downloads)
        consumers = [s for s in ci['qualification']['steps'] if s.get('env', {}).get('DECISION_DIRECTORY') == 'qualified-distribution']
        consumers += [s for job in workflow('release.yml')['jobs'].values() for s in job.get('steps', [])
                      if s.get('env', {}).get('DECISION_DIRECTORY') == 'qualified-distribution']
        self.assertEqual(len(consumers), 3)
        for step in consumers:
            self.assertTrue(step['run'].endswith(' ci:decision:download'))
            self.assertEqual(step['env']['CANDIDATE_REQUIRED'], 'true')
            self.assertEqual(step['env']['CANDIDATE_WORKFLOW'], '.github/workflows/ci.yml')


if __name__ == '__main__':
    unittest.main()
