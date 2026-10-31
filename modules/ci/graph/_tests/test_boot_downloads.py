#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Download once while retaining real ISO hashing and original provenance checks."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
GRAPH_SOURCE = Path(__file__).resolve().parents[1] / '_source'
sys.path.insert(0, str(GRAPH_SOURCE))
from bindings import digest
import transfer

INSTALLER = ROOT / 'modules/features/installer/_source'
BOOT_SOURCE = Path(os.environ.get('MAESTRO_BOOT_EVIDENCE_SOURCE', INSTALLER / 'boot-evidence.py'))
VERIFY_SOURCE = Path(os.environ.get('MAESTRO_INVENTORY_VERIFIER_SOURCE', INSTALLER / 'verify-inventory.sh'))
BOOT_COMMAND = Path(os.environ.get('MAESTRO_BOOT_COMMAND_SOURCE', INSTALLER / 'boot-media.sh'))
WORKFLOW = Path(os.environ.get('MAESTRO_CI_WORKFLOW', ROOT / '.github/workflows/ci.yml'))
SPEC = importlib.util.spec_from_file_location('download_boot_evidence', BOOT_SOURCE)
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)
PRODUCER = dict(GITHUB_REPOSITORY='closure-labs/maestro', GITHUB_SHA='a'*40,
                GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='2')
SOURCE = 'd'*40
MEDIA = 'c'*64
POLICY = 'b'*64
ISO = b'Actual tiny ISO bytes for binding fixtures\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def selected(expression, mode):
    """Interpret only the two download guard forms present in the real workflow."""
    match = re.fullmatch(r"contains\(fromJSON\('([^']+)'\), fromJSON\(needs.route.outputs.plan\).qualification.mode\)", expression)
    if match:
        return mode in json.loads(match[1])
    if expression == "fromJSON(needs.route.outputs.plan).qualification.mode != 'reuse'":
        return mode != 'reuse'
    raise AssertionError('Unexpected workflow guard: ' + expression)


class DownloadContract(unittest.TestCase):
    def test_all_modes_and_signing_keep_the_required_bytes(self):
        workflow = json.loads(subprocess.check_output(['yq', '-o=json', '.', str(WORKFLOW)], text=True))
        steps = {step.get('name'): step for step in workflow['jobs']['boot']['steps']}
        current = steps['Download maestro-installer']
        retained = steps['Download original media for retained boot verification']
        execute = steps['Boot the installer ISO']
        for mode, expected in {'qualify-media': (True, False, True),
                               'qualify-media-reuse-evidence': (True, False, True),
                               'refresh-evidence': (False, True, False),
                               'reuse': (False, True, False), 'skip': (False, False, False)}.items():
            observed = tuple(selected(step['if'], mode) for step in (current, retained, execute))
            self.assertEqual(observed, expected, mode)
            self.assertLessEqual(sum(observed[:2]), 1)
        self.assertEqual(current['with']['run-id'], '${{ github.run_id }}')
        self.assertEqual(retained['with']['run-id'], '${{ fromJSON(needs.route.outputs.plan).qualification.media_run_id }}')
        self.assertEqual(retained['with']['path'], 'reused-media')
        signing = workflow['jobs']['signing']
        self.assertIn("github.ref == 'refs/heads/main'", signing['if'])
        inventory = next(s for s in signing['steps'] if s.get('name') == 'Download inventory to sign')
        self.assertTrue(selected(inventory['if'], 'refresh-evidence'))
        self.assertTrue(selected(inventory['if'], 'qualify-media'))
        self.assertFalse(selected(inventory['if'], 'reuse'))
        for name in ('Attest complete installer inventory', 'Bind the SPDX SBOM to the installer'):
            step = next(s for s in signing['steps'] if s.get('name') == name)
            self.assertIn('result-installer/iso/maestro-installer.iso', step['with']['subject-path'])


class BootBytes(unittest.TestCase):
    def execute(self, mode='refresh-evidence', mutation=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained = root / 'reused-media'
            retained.mkdir()
            iso = retained / 'result-installer/iso/maestro-installer.iso'
            iso.parent.mkdir(parents=True)
            iso.write_bytes(ISO)
            state = dict(schema_version=5, mode='qualify-media', media_input=MEDIA,
                         evidence_input='e'*64, source_commit=SOURCE, artifact_source_commit=SOURCE,
                         media_source_commit=SOURCE, producer_event='push', artifact_run_id=17,
                         media_run_id=17, evidence_run_id=18)
            (retained / 'maestro-qualification-state.json').write_text(json.dumps(state))
            originals = {}
            names = ['result-installer/iso/maestro-installer.iso',
                     'maestro-system.spdx.json', 'maestro-system.cdx.json',
                     'xen-orchestra-supply.assertion.json', 'xen-orchestra-supply.spdx.json',
                     'xen-orchestra-supply.cdx.json']
            for name in names:
                path = retained / name
                if name.endswith('.json'):
                    path.write_text(json.dumps({'spdxVersion': 'SPDX-2.3', 'fixture': name}))
                originals[name] = sha(path.read_bytes())
                (retained / (Path(name).name + '.sha256')).write_text(originals[name] + '  ' + name + '\n')
            originals['maestro-qualification-state.json'] = sha((retained / 'maestro-qualification-state.json').read_bytes())
            (root / 'signed-subjects.json').write_text(json.dumps(originals))
            graph = {'policy': {'boot': POLICY, 'bootCommand': sha(BOOT_COMMAND.read_bytes())},
                     'transport': {'inventory': []}}
            (root / 'ci-graph').mkdir()
            (root / 'ci-graph/candidate.json').write_text(json.dumps(graph))
            (root / 'ci-graph/plan.json').write_text(json.dumps({'candidateRevision': PRODUCER['GITHUB_SHA'],
                                                              'candidateGraphSha256': digest(graph)}))
            inventory = dict(schemaVersion=2, phase='inventory', producer=PRODUCER, graphSha256=digest(graph),
                             targets=[], roots=[], transport={}, files={},
                             evidenceFiles={name:'e'*64 for name in transfer.EVIDENCE_FILES}, isoSha256=sha(ISO))
            (root / 'inventory-binding').mkdir()
            (root / 'inventory-binding/manifest.json').write_text(json.dumps(inventory))
            binary = root / 'bin'; binary.mkdir()
            def script(name, text):
                path = binary / name
                path.write_text('#!' + sys.executable + '\n' + text)
                path.chmod(0o755)
            # Exercise the real inventory shell verifier. Only remote GitHub
            # attestations/run metadata are replaced by immutable fixture truth.
            wrapper = binary / 'maestro-ci-verify-inventory'
            wrapper.write_text('#!/bin/sh\nexec bash "$TEST_INVENTORY_VERIFIER" "$@"\n')
            wrapper.chmod(0o755)
            script('maestro-ci-validate-state', 'import json,sys\nx=json.load(open(sys.argv[1])); assert x["schema_version"]==5\n')
            script('maestro-ci-trusted-run', '''import json,sys
assert sys.argv[1:]==['--batch']
x=json.load(sys.stdin)
assert x==[{'run_id':17,'source_sha':'d'*40},{'run_id':17,'source_sha':'d'*40},{'run_id':18,'source_sha':''}]
''')
            script('gh', '''import hashlib,json,os,sys
from pathlib import Path
a=sys.argv[1:]; assert a[:2]==['attestation','verify']
p=Path(a[2]); relative=str(p.relative_to(Path.cwd()/'reused-media'))
subjects=json.load(open('signed-subjects.json'))
assert hashlib.sha256(p.read_bytes()).hexdigest()==subjects[relative]
for flag,value in [('--repo','closure-labs/maestro'),('--signer-workflow','closure-labs/maestro/.github/workflows/ci.yml'),('--source-ref','refs/heads/main'),('--source-digest','d'*40),('--signer-digest','d'*40)]:
 assert a[a.index(flag)+1]==value
assert '--deny-self-hosted-runners' in a
assert os.environ.get('TEST_DENY_ATTESTATION')!='true'
with open('verified-files.jsonl','a') as out: out.write(json.dumps(relative)+'\\n')
if '--predicate-type' in a:
 print(json.dumps([{'verificationResult':{'statement':{'predicate':json.load(open('reused-media/maestro-system.spdx.json'))}}}]))
''')
            env = dict(os.environ, **PRODUCER, QUALIFICATION_MODE=mode, EXPECTED_MEDIA_INPUT=MEDIA,
                       MAESTRO_BOOT_POLICY_SHA256=POLICY, MAESTRO_BOOT_VERIFIER=str(BOOT_COMMAND),
                       BOOT_LOG=str(root / 'boot.log'), TEST_INVENTORY_VERIFIER=str(VERIFY_SOURCE),
                       PATH=str(binary)+os.pathsep+os.environ['PATH'], GH_BIN='gh',
                       GITHUB_OUTPUT=str(root/'github-output'), GITHUB_STEP_SUMMARY=str(root/'summary'),
                       TEST_DENY_ATTESTATION='false')
            if mode.startswith('qualify-media'):
                current = root / 'result-installer/iso/maestro-installer.iso'
                current.parent.mkdir(parents=True); current.write_bytes(ISO)
                (root / 'boot.log').write_text('Reached target Multi-User System\n')
            if mutation:
                mutation(root, env)
            # Bind fixture manifests after intentional content mutations, so a
            # test can isolate a wrong signed ISO or producer from byte corruption.
            env['GRAPH_PLAN_SHA256'] = sha((root / 'ci-graph/plan.json').read_bytes())
            env['INVENTORY_MANIFEST_SHA256'] = sha((root / 'inventory-binding/manifest.json').read_bytes())
            if env.get('TEST_BAD_MANIFEST_DIGEST'):
                env['INVENTORY_MANIFEST_SHA256'] = 'f'*64
            if env.get('TEST_BAD_PLAN_DIGEST'):
                env['GRAPH_PLAN_SHA256'] = 'f'*64
            subprocess_run = subprocess.run
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, env), patch.object(boot.subprocess, 'run',
                        side_effect=lambda *args, **kwargs: subprocess_run(*args, **dict(kwargs, stderr=subprocess.DEVNULL))):
                    try:
                        boot.main()
                    except (ValueError, OSError, subprocess.CalledProcessError):
                        return None
            finally:
                os.chdir(previous)
            result = json.loads((root / 'boot-result.json').read_text())
            verified = [json.loads(line) for line in (root / 'verified-files.jsonl').read_text().splitlines()] if (root / 'verified-files.jsonl').exists() else []
            return result, verified, (root / 'result-installer').exists()

    def test_refresh_verifies_real_retained_iso_without_current_download(self):
        result, verified, current = self.execute()
        self.assertFalse(current)
        self.assertEqual(result['isoSha256'], sha(ISO))
        self.assertEqual(result['disposition'], 'verified-retained')
        self.assertIsNone(result['bootLogSha256'])
        self.assertEqual(result['producer'], PRODUCER)
        self.assertEqual(result['origin'], {'revision':SOURCE,'runId':17})
        self.assertIn('result-installer/iso/maestro-installer.iso', verified)
        self.assertIn('maestro-qualification-state.json', verified)
        self.assertEqual(len(verified), 8)  # six subjects, state, SPDX predicate

    def test_fresh_modes_still_require_current_bytes_and_boot_log(self):
        for mode in ('qualify-media','qualify-media-reuse-evidence'):
            result, verified, current = self.execute(mode)
            self.assertTrue(current)
            self.assertEqual(result['disposition'],'executed')
            self.assertEqual(result['origin'], PRODUCER)
            self.assertTrue(result['bootLogSha256'])
            self.assertFalse(verified)
            self.assertIsNone(self.execute(mode, lambda root, env: (root/'boot.log').write_text('no boot success')))
            self.assertIsNone(self.execute(mode, lambda root, env: (root/'result-installer/iso/maestro-installer.iso').unlink()))

    def test_bad_retained_bytes_checksums_attestations_and_provenance_fail(self):
        def corrupt_both(root, env):
            (root/'reused-media/result-installer/iso/maestro-installer.iso').write_bytes(b'wrong')
            (root/'reused-media/maestro-installer.iso.sha256').write_text(sha(b'wrong')+'  result-installer/iso/maestro-installer.iso\n')
        def change_state(root, env):
            path=root/'reused-media/maestro-qualification-state.json'
            state=json.loads(path.read_text()); state['media_run_id']=99
            path.write_text(json.dumps(state))
        def change_source(root,env):
            path=root/'reused-media/maestro-qualification-state.json'
            state=json.loads(path.read_text()); state['artifact_source_commit']='e'*40
            path.write_text(json.dumps(state))
        def symlink(root, env):
            path=root/'reused-media/result-installer/iso/maestro-installer.iso'
            path.unlink(); path.symlink_to(root/'signed-subjects.json')
        mutations=[lambda root,env:(root/'reused-media/result-installer/iso/maestro-installer.iso').write_bytes(b'wrong'),
                   lambda root,env:(root/'reused-media/result-installer/iso/maestro-installer.iso').unlink(),
                   lambda root,env:(root/'reused-media/maestro-installer.iso.sha256').write_text('0'*64+'  bad/path\n'),
                   lambda root,env:env.update(TEST_DENY_ATTESTATION='true'),
                   lambda root,env:env.update(EXPECTED_MEDIA_INPUT='f'*64), corrupt_both,change_state,change_source,symlink]
        for mutation in mutations:
            self.assertIsNone(self.execute(mutation=mutation))

    def test_inventory_attempt_digest_media_and_policy_bindings_fail_closed(self):
        def manifest_change(key,value):
            def change(root,env):
                path=root/'inventory-binding/manifest.json'
                data=json.loads(path.read_text()); data[key]=value
                path.write_text(json.dumps(data))
            return change
        mutations=[manifest_change('isoSha256','f'*64),
                   manifest_change('producer',dict(PRODUCER,GITHUB_RUN_ATTEMPT='1')),
                   manifest_change('producer',dict(PRODUCER,GITHUB_SHA='e'*40)),
                   manifest_change('graphSha256','f'*64),
                   lambda root,env:env.update(MAESTRO_BOOT_POLICY_SHA256='f'*64),
                   lambda root,env:env.update(TEST_BAD_MANIFEST_DIGEST='true'),
                   lambda root,env:env.update(TEST_BAD_PLAN_DIGEST='true'),
                   lambda root,env:env.update(MAESTRO_BOOT_VERIFIER=str(root/'signed-subjects.json'))]
        for mutation in mutations:
            self.assertIsNone(self.execute(mutation=mutation))
        self.assertEqual(self.execute('reuse')[0]['disposition'],'verified-retained')
        self.assertIsNone(self.execute('skip'))


if __name__ == '__main__':
    unittest.main()
