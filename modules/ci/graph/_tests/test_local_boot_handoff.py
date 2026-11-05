#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Same-attempt byte handoff cannot synthesize boot execution or waive proof."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('MAESTRO_LOCAL_BOOT_RESULT_SOURCE', Path(__file__).parents[4]/'modules/features/installer/_source/verify-local-boot-result.py'))
sys.path.insert(0,str(Path(__file__).parents[1]/'_source'))
from bindings import digest
import transfer
spec = importlib.util.spec_from_file_location('local_boot_handoff',SOURCE)
handoff = importlib.util.module_from_spec(spec); spec.loader.exec_module(handoff)
PRODUCER = dict(GITHUB_REPOSITORY='closure-labs/maestro',GITHUB_SHA='a'*40,GITHUB_RUN_ID='42',GITHUB_RUN_ATTEMPT='2')


class Handoff(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.previous=Path.cwd();os.chdir(self.root);self.addCleanup(os.chdir,self.previous)
        self.graph={'policy':{'boot':'b'*64},'transport':{'inventory':[]}}
        self.plan={'candidateRevision':PRODUCER['GITHUB_SHA'],'candidateGraphSha256':digest(self.graph)}
        Path('ci-graph').mkdir();Path('ci-graph/candidate.json').write_text(json.dumps(self.graph));Path('ci-graph/plan.json').write_text(json.dumps(self.plan))
        self.inventory=dict(schemaVersion=2,phase='inventory',producer=PRODUCER,graphSha256=digest(self.graph),targets=[],roots=[],transport=None,files={},evidenceFiles={n:'e'*64 for n in transfer.EVIDENCE_FILES},isoSha256='c'*64)
        Path('inventory-binding').mkdir();Path('inventory-binding/manifest.json').write_text(json.dumps(self.inventory))
        self.result=dict(schemaVersion=1,disposition='verified-retained',producer=PRODUCER,origin={'revision':'d'*40,'runId':17},graphSha256=digest(self.graph),mediaInput='f'*64,verifierSha256='b'*64,isoSha256='c'*64,bootLogSha256=None)
        self.env=dict(PRODUCER,QUALIFICATION_MODE='refresh-evidence',EXPECTED_MEDIA_INPUT='f'*64,
                      GRAPH_PLAN_SHA256=hashlib.sha256(Path('ci-graph/plan.json').read_bytes()).hexdigest(),
                      INVENTORY_MANIFEST_SHA256=hashlib.sha256(Path('inventory-binding/manifest.json').read_bytes()).hexdigest(),GITHUB_OUTPUT=str(self.root/'output'))

    def invoke(self,result=None,env=None,raw=None):
        raw=raw if raw is not None else json.dumps(self.result if result is None else result).encode()
        Path('boot-result.json').write_bytes(raw)
        settings=dict(self.env,LOCAL_BOOT_RESULT_SHA256=hashlib.sha256(raw).hexdigest()); settings.update(env or {})
        with patch.dict(os.environ,settings): handoff.main()
        self.assertEqual(Path('boot-result.json').read_bytes(),raw)

    def test_exact_bytes_retained_without_iso_or_network(self):
        self.invoke();self.assertEqual(Path('output').read_text(), 'manifest_sha256=' + hashlib.sha256(Path('boot-result.json').read_bytes()).hexdigest() + '\n')
        self.assertFalse(Path('result-installer').exists())

    def test_real_command_emits_one_output_line_and_rejects_corrupt_record(self):
        self.invoke()
        Path('output').unlink()
        env = dict(os.environ, **self.env,
                   LOCAL_BOOT_RESULT_SHA256=hashlib.sha256(Path('boot-result.json').read_bytes()).hexdigest(),
                   PYTHONPATH=str(Path(transfer.__file__).parent))
        result = subprocess.run([sys.executable, str(SOURCE.resolve())], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path('output').read_text().splitlines(), ['manifest_sha256=' + env['LOCAL_BOOT_RESULT_SHA256']])
        Path('output').unlink()
        Path('boot-result.json').write_text('{}')
        result = subprocess.run([sys.executable, str(SOURCE.resolve())], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(Path('output').exists())
        self.assertEqual(result.stderr.strip(), 'Local retained-boot handoff validation failed')

    def test_wrong_run_attempt_revision_graph_media_iso_or_policy_reject(self):
        for key,value in [('graphSha256','e'*64),('mediaInput','e'*64),('isoSha256','e'*64),('verifierSha256','e'*64),('disposition','executed'),('bootLogSha256','e'*64),('schemaVersion',True)]:
            changed=dict(self.result,**{key:value})
            with self.subTest(key=key),self.assertRaises((ValueError,TypeError)):self.invoke(changed)
        for key,value in [('GITHUB_RUN_ID','41'),('GITHUB_RUN_ATTEMPT','1'),('GITHUB_SHA','e'*40)]:
            changed=copy.deepcopy(self.result);changed['producer'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.invoke(changed)

    def test_missing_or_changed_origin_fails(self):
        for origin in ({},{'revision':'x','runId':17},{'revision':'d'*40,'runId':True}):
            with self.assertRaises(ValueError):self.invoke(dict(self.result,origin=origin))

    def test_current_digest_and_inventory_binding_are_required(self):
        for values in ({'LOCAL_BOOT_RESULT_SHA256':'e'*64},{'INVENTORY_MANIFEST_SHA256':'e'*64},{'GRAPH_PLAN_SHA256':'e'*64},{'QUALIFICATION_MODE':'reuse'}):
            with self.subTest(values=values),self.assertRaises(ValueError):self.invoke(env=values)

    def test_duplicate_oversized_and_nonregular_records_reject(self):
        for raw in (b'{"schemaVersion":1,"schemaVersion":1}',b'x'*65537):
            with self.assertRaises(ValueError):self.invoke(raw=raw)
        Path('boot-result.json').unlink();Path('other').write_text('{}');Path('boot-result.json').symlink_to('other')
        with patch.dict(os.environ,dict(self.env,LOCAL_BOOT_RESULT_SHA256='e'*64)),self.assertRaises(OSError):handoff.main()

    def test_real_hardlink_handoff_preserves_regular_bytes_without_copy(self):
        original=Path('reused-media/result-installer/iso/maestro-installer.iso');original.parent.mkdir(parents=True);original.write_bytes(b'fixture ISO bytes')
        subprocess.run(['cp','-al','--','reused-media/result-installer','result-installer'],check=True)
        current=Path('result-installer/iso/maestro-installer.iso')
        self.assertFalse(current.is_symlink());self.assertEqual(current.stat().st_ino,original.stat().st_ino)
        self.assertEqual(current.read_bytes(),original.read_bytes())


if __name__=='__main__':unittest.main()
