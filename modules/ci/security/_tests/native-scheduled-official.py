#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Same-invocation deduplication and explicit scheduled shipped-product coverage."""
from contextlib import redirect_stdout,contextmanager
from copy import deepcopy
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=module('scheduled_official_fixture',Path(__file__).with_name('native-official-refresh.py'))
refresh=fixture.refresh;target=fixture.target
stage=module('scoped_health_stage',ROOT/'modules/ci/security/_source/native-stage.py')
workflow=module('schedule_workflow',Path(__file__).with_name('native-refresh-workflow.py')).workflow
S=fixture.fixture.S;M=fixture.fixture.M;P=fixture.fixture.P

class Scheduled(unittest.TestCase):
    def setUp(self):
        self.env=dict(GITHUB_REPOSITORY='closure-labs/maestro',GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='schedule',
            GITHUB_SHA=P,GITHUB_RUN_ID='20',GITHUB_RUN_ATTEMPT='1',MAESTRO_NATIVE_REFRESH_ENABLED='true',MAESTRO_NATIVE_RELEASE_ENABLED='true')
        self.product=dict(runId=7,runAttempt=2,revision=S,releaseId=3,tag='v1.2.3')
        self.reuse=dict(runId=7,runAttempt=2,revision=S,healthRunId=20,healthRunAttempt=1,policyRevision=P,
            expiresAt=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat())
    def test_same_exact_producer_reuses_only_this_invocation(self):
        with patch.dict(os.environ,self.env):
            self.assertTrue(refresh.reuse_same_product(self.product,json.dumps(self.reuse)))
            self.assertFalse(refresh.reuse_same_product(dict(self.product,runAttempt=3),json.dumps(self.reuse)))
            self.assertFalse(refresh.reuse_same_product(self.product,''))
            for change in (dict(healthRunId=19),dict(healthRunAttempt=2),dict(policyRevision=M),dict(runId=True),dict(expiresAt='2000-01-01T00:00:00Z'),dict(expiresAt='2099-01-01T00:00:00Z')):
                with self.subTest(change=change),self.assertRaises(ValueError):refresh.reuse_same_product(self.product,json.dumps(dict(self.reuse,**change)))
            for raw in ('{"runId":7,"runId":7}',' '*4097,'{"runId":NaN}'):
                with self.assertRaises(ValueError):refresh.reuse_same_product(self.product,raw)
    def test_both_flags_and_protected_schedule_required_before_any_read(self):
        for change in (dict(GITHUB_EVENT_NAME='workflow_dispatch'),dict(MAESTRO_NATIVE_RELEASE_ENABLED='false'),dict(MAESTRO_NATIVE_REFRESH_ENABLED='false'),dict(GITHUB_REF='refs/heads/topic')):
            with patch.dict(os.environ,dict(self.env,**change)),self.assertRaises(ValueError):refresh.scheduled_official(P,api=lambda p:(_ for _ in ()).throw(AssertionError('No read')))
    def test_standard_latest_release_selection_still_authenticates_exact_receipt(self):
        latest=dict(id=3,tag_name='v1.2.3',draft=False,prerelease=False);calls=[]
        def fetch(*args,**kwargs):calls.append((args,kwargs));return self.product
        with patch.dict(os.environ,self.env),patch.object(refresh,'module',return_value=SimpleNamespace(fetch=fetch)):
            self.assertEqual(refresh.scheduled_official(P,api=lambda p:latest),self.product)
            self.assertEqual(calls,[(('v1.2.3',None,P),{'discover_signer':True})])
            for change in (dict(draft=True),dict(prerelease=True),dict(tag_name='invalid'),dict(id=9)):
                with self.subTest(change=change),self.assertRaises(ValueError):refresh.scheduled_official(P,api=lambda p:dict(latest,**change))
    def test_official_pointer_and_main_changes_reject(self):
        def api(path):return dict(id=3,tag_name='v1.2.3',draft=False,prerelease=False) if path=='releases/latest' else {'object':{'sha':P}}
        with patch.dict(os.environ,self.env):
            refresh.official_current(self.product,api)
            with self.assertRaises(ValueError):refresh.official_current(dict(self.product,releaseId=9),api)
            with self.assertRaises(ValueError):refresh.official_current(self.product,lambda p:api(p) if p=='releases/latest' else {'object':{'sha':M}})
    def test_deduplicated_pipeline_performs_no_second_stage_restore_or_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            env=dict(self.env,NATIVE_REFRESH_REUSE_PRODUCT=json.dumps(self.reuse),GITHUB_OUTPUT=str(Path(tmp)/'outputs'))
            argv=['refresh','--select-official-release','--policy-revision',P,'--output',str(Path(tmp)/'report')]
            with patch.dict(os.environ,env),patch.object(sys,'argv',argv),patch.object(refresh,'scheduled_official',return_value=self.product),patch.object(refresh,'official_current') as current,patch.object(refresh,'module',side_effect=AssertionError('No duplicate inventory/transport/scanner')),redirect_stdout(io.StringIO()) as out:
                refresh.main();self.assertIn('same-invocation-product-health-reused',out.getvalue());current.assert_called_once_with(self.product)
            self.assertFalse((Path(tmp)/'report').exists());self.assertEqual((Path(tmp)/'outputs').read_text(),'reused=true\n')
    def test_distinct_official_product_keeps_full_verification_scan_and_pointer_race_cleanup(self):
        case=fixture.Official();case.setUp();self.addCleanup(case.doCleanups)
        product=dict(case.target,releaseId=3,tag='v1.2.3');events=[]
        @contextmanager
        def verified(*args,**kwargs):events.append('original-CI-and-boot');yield case.bundle
        owner=refresh.module
        stage=SimpleNamespace(stage_refresh=lambda *a,**k:events.append('stage'),transport=lambda *a:None)
        distribution=SimpleNamespace(restore=lambda *a:None)
        def lookup(name,path):return stage if name=='refresh_stage' else distribution if name=='refresh_distribution' else owner(name,path)
        output=Path(case.case.temp.name)/'fresh'
        def scan(bundle,destination,*args,**kwargs):
            self.assertTrue(kwargs['scheduled']);events.append('one-refresh');Path(destination).mkdir()
            return dict(originalProducer={k:product[k] for k in ('runId','runAttempt','revision')},expiresAt=self.reuse['expiresAt'],sourceRevision=S,producer={})
        env=dict(self.env,NATIVE_REFRESH_REUSE_PRODUCT='',GITHUB_OUTPUT='',MAESTRO_NATIVE_PREPARE_POLICY=str(ROOT/'modules/ci/authority/_source/decision-policy.json'))
        argv=['refresh','--select-official-release','--policy-revision',P,'--output',str(output)]
        with patch.dict(os.environ,env),patch.object(sys,'argv',argv),patch.object(refresh,'scheduled_official',return_value=product),patch.object(refresh,'module',side_effect=lookup),patch.object(refresh.native,'verified_inventory',side_effect=verified),patch.object(refresh,'refresh',side_effect=scan),patch.object(refresh,'official_current'),redirect_stdout(io.StringIO()):
            refresh.main();self.assertEqual(events,['stage','original-CI-and-boot','one-refresh'])
            output.rmdir();events.clear()
            with patch.object(refresh,'official_current',side_effect=ValueError('latest release changed')),self.assertRaises(ValueError):refresh.main()
            self.assertFalse(output.exists());self.assertEqual(events,['stage','original-CI-and-boot','one-refresh'])

    def test_job_outputs_are_bound_to_verified_producer_and_current_health_run(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,self.env):
            path=Path(tmp)/'outputs';os.environ['GITHUB_OUTPUT']=str(path)
            manifest=dict(originalProducer={k:self.product[k] for k in ('runId','runAttempt','revision')},expiresAt=self.reuse['expiresAt'])
            refresh.job_outputs(manifest,scoped=True)
            rows=dict(line.split('=',1) for line in path.read_text().splitlines())
            self.assertEqual(json.loads(rows['verified_product']),self.reuse)
            self.assertEqual(rows['health_artifact'],'maestro-native-health-7-2-'+S)
    def test_scoped_health_is_exact_not_newest_and_never_falls_back_after_failure(self):
        row=dict(id=1,name='maestro-native-health',expired=False,expires_at='2099-01-01T00:00:00Z',digest='sha256:'+'f'*64,workflow_run=dict(id=20,head_sha=P,head_branch='main'))
        scoped=dict(row,id=2,name='maestro-native-health-7-2-'+S)
        with patch.object(stage,'api',return_value={'artifacts':[row,scoped]}):self.assertEqual(stage.select(20,P,row['name'],alternate=scoped['name'])['id'],2)
        for rows in ([row,dict(scoped,expired=True)],[row,scoped,scoped]):
            with patch.object(stage,'api',return_value={'artifacts':rows}),self.assertRaises(ValueError):stage.select(20,P,row['name'],alternate=scoped['name'])
        with patch.object(stage,'api',return_value={'artifacts':[row]}):self.assertEqual(stage.select(20,P,row['name'],alternate=scoped['name'])['id'],1)
    def test_untrusted_signer_hint_is_still_verified_not_admitted(self):
        case=fixture.Official();case.setUp();self.addCleanup(case.doCleanups)
        result=target.fetch('v1.2.3',None,P,api=case.case.api,verify=case.case.verify,execute=case.execute,discover_signer=True)
        self.assertEqual(result['runId'],7);self.assertIn(M,case.case.command)
        case.case.receipt['policyRevision']='e'*40;case.case.write();case.raw=case.case.path.read_bytes()
        def verify(*args):
            self.assertEqual(args[args.index('--source-digest')+1],'e'*40)
            raise ValueError('Signature does not bind hinted signer')
        with self.assertRaises(ValueError):target.fetch('v1.2.3',None,P,api=case.case.api,verify=verify,execute=case.execute,discover_signer=True)
    def test_schedule_truth_table_replaces_only_activated_legacy_official_route(self):
        import re
        data=workflow('security.yml')
        for rolling in ('false','true'):
            for release in ('false','true'):
                for result in ('success','failure','skipped'):
                    values={'github.event_name':'schedule','github.repository':'closure-labs/maestro','github.ref':'refs/heads/main',
                        'vars.MAESTRO_NATIVE_REFRESH_ENABLED':rolling,'vars.MAESTRO_NATIVE_RELEASE_ENABLED':release,
                        'inputs.policy_only':False,'inputs.native_refresh':False,'inputs.native_official_tag':'',
                        'inputs.native_official_publication_revision':'','needs.native_refresh.result':result}
                    def condition(name):
                        expression=' '.join(data['jobs'][name]['if'].split()).replace('!cancelled()','True')
                        expression=re.sub(r'(?:github|vars|inputs|needs)\.[A-Za-z_.]+',lambda m:repr(values[m.group()]),expression)
                        expression=expression.replace('&&',' and ').replace('||',' or ')
                        expression=re.sub(r'\btrue\b','True',expression);expression=re.sub(r'\bfalse\b','False',expression)
                        return eval(expression,{'__builtins__':{},'contains':lambda xs,x:x in xs,'fromJSON':json.loads})
                    with self.subTest(rolling=rolling,release=release,result=result):
                        self.assertEqual(condition('release_candidates'),not(rolling=='true' and release=='true'))
                        self.assertEqual(condition('native_official_refresh'),rolling=='true' and release=='true' and result in ('success','failure'))
                        self.assertEqual(condition('native_refresh'),rolling=='true')

    def test_native_job_dependency_and_both_flags_preserve_default_routing(self):
        data=workflow('security.yml');job=data['jobs']['native_official_refresh'];self.assertEqual(job['needs'],'native_refresh')
        self.assertIn('needs.native_refresh.result',job['if']);self.assertEqual(job['permissions'],data['jobs']['native_refresh']['permissions'])
        for flag in ('MAESTRO_NATIVE_RELEASE_ENABLED','MAESTRO_NATIVE_REFRESH_ENABLED'):
            self.assertIn(flag,job['if']);self.assertIn(flag,data['jobs']['release_candidates']['if'])
        step=next(s for s in job['steps'] if s.get('id')=='refresh')
        self.assertEqual(step['env']['NATIVE_REFRESH_SELECT_OFFICIAL'],'true')
        self.assertIn("needs.native_refresh.result == 'success'",step['env']['NATIVE_REFRESH_REUSE_PRODUCT'])
        for s in job['steps']:
            if s.get('uses','').startswith(('actions/attest@','actions/upload-artifact@')):self.assertEqual(s['if'],"steps.refresh.outputs.reused != 'true'")
        self.assertNotIn('secrets.',json.dumps(job));self.assertNotIn('packages',job['permissions'])

if __name__=='__main__':unittest.main()
