#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real ZIP subprocess boundaries and exact artifact selection, with no credentials."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('stage',ROOT/'modules/ci/security/_source/native-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)


class ArtifactStage(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.bin=self.root/'bin';self.bin.mkdir();fake=self.bin/'gh'
        fake.write_text('#!'+sys.executable+'\nimport os,sys\nfrom pathlib import Path\nassert sys.argv[1:4]==["api","--method","GET"]\nassert sys.argv[4]=="https://api.github.com/repos/closure-labs/maestro/actions/artifacts/1/zip"\nsys.stdout.buffer.write(Path(os.environ["FIXTURE_ARCHIVE"]).read_bytes())\n')
        fake.chmod(0o700);self.target=self.root/'selected';self.target.mkdir();self.archive=self.root/'fixture.zip'

    def make(self,entries):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(self.archive,'w',zipfile.ZIP_DEFLATED) as z:
                for name,value in entries:z.writestr(name,value)
        return dict(id=1,size_in_bytes=self.archive.stat().st_size,
            archive_download_url='https://api.github.com/repos/closure-labs/maestro/actions/artifacts/1/zip',
            digest='sha256:'+hashlib.sha256(self.archive.read_bytes()).hexdigest())

    def download(self,row,names=None,limit=65536):
        with patch.dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ['PATH'],FIXTURE_ARCHIVE=str(self.archive)):
            stage.download(row,self.target,names if names is not None else {'item.json':'item.json'},[0],limit)

    def test_real_download_validates_zip_hash_and_extracts_only_selected_files(self):
        row=self.make([('item.json','{}'),('unused.json','not an input')]);self.download(row)
        self.assertEqual([p.name for p in self.target.iterdir()],['item.json'])

    def test_hash_endpoint_and_expansion_limits_fail_closed(self):
        row=self.make([('item.json','x'*10000)])
        for bad in (dict(row,digest='sha256:'+'0'*64),dict(row,archive_download_url='https://example.test/leak')):
            with self.subTest(row=bad),self.assertRaises(ValueError):self.download(bad)
        with self.assertRaises(ValueError):self.download(row,limit=1000)
        self.assertEqual(list(self.target.iterdir()),[])

    def test_missing_duplicate_traversal_and_special_members_reject(self):
        symlink=zipfile.ZipInfo('unselected');symlink.create_system=3;symlink.external_attr=(stat.S_IFLNK|0o777)<<16
        fifo=zipfile.ZipInfo('unselected');fifo.create_system=3;fifo.external_attr=(stat.S_IFIFO|0o600)<<16
        cases=[[('missing.json','{}')],[('../escape','x'),('item.json','{}')],
            [('item.json','{}'),('item.json','{}')],[(symlink,'outside'),('item.json','{}')],[(fifo,''),('item.json','{}')]]
        for entries in cases:
            for p in self.target.iterdir():p.unlink()
            with self.subTest(entries=str(entries)),self.assertRaises((ValueError,FileExistsError)):
                self.download(self.make(entries))
        self.assertFalse((self.root/'escape').exists())

    def test_exact_selection_rejects_missing_ambiguous_expired_and_wrong_source(self):
        row=dict(id=1,name='report',expired=False,expires_at='2099-01-01T00:00:00Z',digest='sha256:'+'a'*64,
            workflow_run=dict(id=7,head_sha='b'*40,head_branch='main'))
        for rows in ([],[row,row],[dict(row,expired=True)],
                     [dict(row,expires_at='2000-01-01T00:00:00Z')],
                     [dict(row,workflow_run=dict(row['workflow_run'],head_sha='c'*40))]):
            with self.subTest(rows=rows),patch.object(stage,'api',return_value={'artifacts':rows}),self.assertRaises(ValueError):
                stage.select(7,'b'*40,'report')
        with patch.object(stage,'api',return_value={'artifacts':[row]}):self.assertEqual(stage.select(7,'b'*40,'report')['id'],1)


class StagePurpose(unittest.TestCase):
    def test_refresh_fetches_only_original_inputs_and_never_a_transport(self):
        for refresh in (False,True):
            with tempfile.TemporaryDirectory() as temporary:
                destination=Path(temporary)/'data';seen=[]
                def select(run,revision,name):
                    self.assertNotIn('transport',name);return {'name':name}
                def download(row,directory,names,budget,limit):
                    seen.append((row['name'],set(names)))
                    for source,target in names.items():
                        value={}
                        if row['name']=='maestro-ci-result':value={'producer':{'GITHUB_RUN_ATTEMPT':'1'},'boot':{'disposition':'executed'}}
                        if row['name']=='maestro-inventory-binding':value={'evidenceFiles':{'document.json':'a'*64}}
                        if row['name']=='maestro-qualification-state':value={'source_commit':'b'*40,'evidence_run_id':7}
                        (directory/target).write_text(json.dumps(value))
                with patch.object(stage,'select',side_effect=select),patch.object(stage,'download',side_effect=download):
                    (stage.stage_refresh if refresh else stage.stage)(destination,7,1,'b'*40,None)
                report=next(names for name,names in seen if name=='maestro-security-report')
                self.assertEqual(report,{'product.json','scans.json','security-result.json'}|(
                    {'inputs.sha256','inventory/Cargo.lock'} if refresh else
                    {'findings.json','source-policy.json','effective-policy.json','critical-applicability.json'}))
                self.assertEqual(sum(name=='maestro-security-report' for name,_ in seen),1)


class ProtectionPlan(unittest.TestCase):
    def test_only_approved_review_changes_then_one_app_check_removal(self):
        p=json.loads((ROOT/'docs/native-cutover/ruleset-20919039-plan.json').read_text())
        before=p['baseline'];a=p['phase_a'];b=p['phase_b']
        clone=json.loads(json.dumps(before))
        review=next(r for r in clone['rules'] if r['type']=='pull_request')['parameters']
        review.update(required_approving_review_count=1,dismiss_stale_reviews_on_push=True,
            require_code_owner_review=True,require_last_push_approval=True)
        self.assertEqual(clone,a)
        checks=next(r for r in clone['rules'] if r['type']=='required_status_checks')['parameters']
        checks['required_status_checks']=[v for v in checks['required_status_checks']
            if v!={'context':'Maintainer decision authority','integration_id':5384448}]
        self.assertEqual(clone,b)
        self.assertTrue(review['require_extra_approval_for_unattributed_changes'])
        self.assertEqual(a['bypass_actors'],[]);self.assertEqual(b['bypass_actors'],[])
        self.assertEqual(sum(v['integration_id']==15368 for v in checks['required_status_checks']),5)


if __name__=='__main__':unittest.main()
