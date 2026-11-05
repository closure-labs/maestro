#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native first-attempt findings review, without cross-publication authority reuse."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import base64
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('publication_fixture',Path(__file__).with_name('native-publication.py'))
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
pub=fixture.pub;risk=pub.risk;SHA='a'*40

class Risk(unittest.TestCase):
    def setUp(self):
        self.case=fixture.Publication();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.case.findings=[self.case.finding('high'),self.case.finding('critical','b')]
        self.bundle=self.case.bundle();self.bundle['normalizedFindings']=[dict(identity='x',severity='High')]
        self.files={'.github/CODEOWNERS':self.case.case.root/'owners'}
        self.files['.github/CODEOWNERS'].write_text('* @human\n')
        self.env=dict(self.case.env,MAESTRO_SYSTEM_ROOT=str(self.case.case.root))
        self.environment=self.case.api('environments/'+risk.ENVIRONMENT)
        self.run=self.case.api('actions/runs/123');self.reviews=self.case.api('actions/runs/123/approvals')
        self.permission=self.case.api('collaborators/human/permission');self.calls=[]
    def api(self,path):
        self.calls.append(path)
        if path.startswith('contents/.github/CODEOWNERS?ref='):
            raw=self.files['.github/CODEOWNERS'].read_bytes()
            return dict(encoding='base64',size=len(raw),content=base64.b64encode(raw).decode())
        if path=='environments/'+risk.ENVIRONMENT:return self.environment
        if path=='actions/runs/123':return self.run
        if path=='actions/runs/123/approvals':return self.reviews
        if path=='collaborators/human/permission':return self.permission
        return self.case.api(path)
    def plan(self,operation='publish'):return risk.plan(self.bundle,self.case.findings,self.files,self.api,operation)
    def state(self,operation='publish'):
        value=self.plan(operation)
        self.env['NATIVE_FINDINGS_CONTEXT_SHA256']=value['contextSha256']
        os.environ['NATIVE_FINDINGS_CONTEXT_SHA256']=value['contextSha256']
        value['rebuild']=lambda:risk.context(self.bundle,self.case.findings,self.files,operation,123)
        return value
    def test_explicit_environment_review_accepts_exact_high_critical_for_only_one_run(self):
        with patch.dict(os.environ,self.env):
            state=self.state();proof=risk.approval(self.api,state)
            self.assertEqual(proof['reviewerId'],risk.REVIEWER_ID)
            self.assertEqual(proof['contextSha256'],state['contextSha256'])
            risk.live(self.api,state,SHA)
        self.assertFalse(any('audit' in p or 'pulls/' in p for p in self.calls))
    def test_release_review_has_one_exact_direct_release_workflow_binding(self):
        self.assertEqual(risk.WORKFLOWS['release'],'.github/workflows/release.yml')
        self.run['path']=risk.WORKFLOWS['release']
        with patch.dict(os.environ,self.env):
            state=self.state('release');risk.approval(self.api,state)
            for wrong in ('.github/workflows/release-publication.yml','.github/workflows/publication.yml'):
                self.run['path']=wrong
                with self.subTest(path=wrong),self.assertRaises(ValueError):risk.approval(self.api,state)

    def test_plan_never_accepts_risk_or_reads_an_approval(self):
        with patch.dict(os.environ,self.env):self.plan()
        self.assertNotIn('actions/runs/123/approvals',self.calls)
    def test_no_approval_rejection_duplicate_or_wrong_environment_rejects(self):
        cases=[[],[dict(self.reviews[0],state='rejected')],self.reviews*2,
            [dict(self.reviews[0],environments=[dict(id=99,name=risk.ENVIRONMENT)])]]
        for reviews in cases:
            with self.subTest(reviews=reviews),patch.dict(os.environ,self.env):
                state=self.state();self.reviews=reviews
                with self.assertRaises(ValueError):risk.approval(self.api,state)
    def test_bot_identity_or_current_access_loss_rejects_and_cannot_revive(self):
        with patch.dict(os.environ,self.env):
            state=self.state();self.permission['permission']='read'
            with self.assertRaises(ValueError):risk.live(self.api,state,SHA)
            self.permission['permission']='write'
            with self.assertRaises(ValueError):risk.live(self.api,state,SHA)
            self.assertTrue(state['invalidated'])
        for user in [dict(type='Bot',id=risk.REVIEWER_ID,login='human'),dict(type='User',id=99,login='human')]:
            with patch.dict(os.environ,self.env):
                state=self.state();self.reviews[0]['user']=user
                with self.assertRaises(ValueError):risk.approval(self.api,state)
    def test_changed_context_or_missing_digest_rejects(self):
        changes=[lambda:self.case.findings[0].update(version='new'),
            lambda:self.bundle['normalizedFindings'][0].update(identity='new'),
            lambda:self.bundle['native'].update(scannedAt='changed'),
            lambda:self.files['.github/CODEOWNERS'].write_text('* @other\n')]
        for change in changes:
            with self.subTest(change=change),patch.dict(os.environ,self.env):
                state=self.state();change()
                with self.assertRaises(ValueError):risk.approval(self.api,state)
        with patch.dict(os.environ,self.env):
            state=self.state();os.environ.pop('NATIVE_FINDINGS_CONTEXT_SHA256')
            with self.assertRaises(ValueError):risk.approval(self.api,state)
    def test_first_attempt_only_exact_run_workflow_main_public_repository(self):
        for key,value in [('GITHUB_RUN_ATTEMPT','2'),('GITHUB_RUN_ID','999'),('GITHUB_SHA','f'*40),('GITHUB_EVENT_NAME','push')]:
            with self.subTest(key=key),patch.dict(os.environ,dict(self.env,**{key:value})):
                with self.assertRaises((ValueError,AssertionError)):self.plan()
        for key,value in [('run_attempt',2),('head_sha','f'*40),('path','.github/workflows/ci.yml')]:
            with self.subTest(key=key),patch.dict(os.environ,self.env),patch.dict(self.run,{key:value}):
                with self.assertRaises(ValueError):self.plan()
        with patch.dict(os.environ,self.env),patch.dict(self.run,created_at=(datetime.now(timezone.utc)-timedelta(days=31)).isoformat()):
            with self.assertRaises(ValueError):self.plan()
    def test_documented_branch_policy_rule_shape_is_required_and_order_independent(self):
        with patch.dict(os.environ,self.env):
            self.environment['protection_rules'].reverse();self.plan()
            self.environment['protection_rules']=[r for r in self.environment['protection_rules'] if r['type']!='branch_policy']
            with self.assertRaises(ValueError):self.plan()

    def test_environment_replacement_bypass_wrong_reviewer_or_unprotected_branch_rejects(self):
        for change in [dict(can_admins_bypass=True),dict(deployment_branch_policy=None),dict(protection_rules=[])]:
            with self.subTest(change=change),patch.dict(os.environ,self.env),patch.dict(self.environment,change):
                with self.assertRaises(ValueError):self.plan()
        with patch.dict(os.environ,self.env):
            state=self.state();self.environment['id']=100
            with self.assertRaises(ValueError):risk.approval(self.api,state)
    def test_free_plan_private_visibility_or_missing_environment_never_runs_unprotected(self):
        original=self.api
        def private(path):
            if path=='':return dict(id=risk.REPO_ID,full_name='closure-labs/maestro',private=True,visibility='private')
            return original(path)
        with patch.dict(os.environ,self.env),self.assertRaises(ValueError):
            risk.plan(self.bundle,self.case.findings,self.files,private,'publish')
        with patch.dict(os.environ,self.env),patch.object(self,'environment',{}),self.assertRaises(ValueError):self.plan()

    def test_denial_or_transport_error_is_never_fallback_authority(self):
        with patch.dict(os.environ,self.env):
            state=self.state()
            def denied(path):
                if path.endswith('/approvals'):raise OSError('denied')
                return self.api(path)
            with self.assertRaises(OSError):risk.approval(denied,state)
            with self.assertRaises(ValueError):risk.approval(self.api,state)
    def test_current_snapshot_cannot_distinguish_unobserved_remove_and_restore(self):
        # This is the explicitly accepted limitation, not a continuity guarantee.
        with patch.dict(os.environ,self.env):
            state=self.state();before=risk.approval(self.api,state)
            self.permission['permission']='read';self.permission['permission']='write'
            self.assertEqual(risk.approval(self.api,state),before)
    def test_protected_review_job_has_no_writer_and_gates_the_disabled_writer(self):
        import subprocess
        data=json.loads(subprocess.run(['yq','-o=json','.',str(fixture.ROOT/'.github/workflows/publication.yml')],
            capture_output=True,text=True,check=True,timeout=10).stdout)
        before=data['jobs']['native_review'];writer=data['jobs']['native_publish']
        self.assertEqual(writer['needs'],'native_review')
        self.assertEqual(writer['environment']['name'],risk.ENVIRONMENT)
        self.assertIn('github.run_id',writer['environment']['url'])
        self.assertNotIn('environment',before)
        for job in (before,writer):
            self.assertIn("vars.MAESTRO_NATIVE_PUBLICATION_ENABLED == 'true'",job['if'])
            self.assertEqual(set(job['permissions'].values()),{'read'})
        self.assertNotIn('secrets.',json.dumps(before))
        review_step=next(s for s in before['steps'] if s.get('id')=='review')
        self.assertIn('ci:native:review',review_step['run'])
        self.assertIn('inputs.native_qualification_only != true',review_step['if'])
        self.assertNotIn('ci:native:publication',review_step['run'])
        step=next(s for s in writer['steps'] if 'NATIVE_FINDINGS_CONTEXT_SHA256' in s.get('env',{}))
        self.assertEqual(step['env']['NATIVE_FINDINGS_CONTEXT_SHA256'],'${{ needs.native_review.outputs.context_sha256 }}')

    def test_real_review_consumer_does_not_accept_findings_or_invoke_a_writer(self):
        root=self.case.case.root;(root/'.github').mkdir();(root/'.github/CODEOWNERS').write_text('* @human\n')
        self.files={'.github/CODEOWNERS':root/'.github/CODEOWNERS'}
        with patch.dict(os.environ,self.env),patch.object(pub,'RISK_POLICY_FILES',tuple(self.files)),patch.object(pub.native,'api',side_effect=self.api):
            value=pub.consume(self.bundle,self.case.policy_path,'review',execute=lambda *a,**k:self.fail('writer called'))
        self.assertEqual(value['verdict']['status'],'blocked')
        self.assertFalse(value['authorization']);self.assertFalse(value['publicationReady'])
        self.assertIn('high/critical',value['notice'])
        self.assertEqual(value['rawFindings'],self.case.findings)
        self.assertNotIn('actions/runs/123/approvals',self.calls)

    def test_qualification_uses_real_gate_without_accepting_risk_or_destination_calls(self):
        root=self.case.case.root;(root/'.github').mkdir();(root/'.github/CODEOWNERS').write_text('* @human\n')
        self.files={'.github/CODEOWNERS':root/'.github/CODEOWNERS'}
        def forbidden(*a,**k):self.fail('Qualification invoked a destination')
        with patch.dict(os.environ,self.env),patch.object(pub,'RISK_POLICY_FILES',tuple(self.files)),patch.object(pub.native,'api',side_effect=self.api):
            self.state('qualify')
            result=pub.consume(self.bundle,self.case.policy_path,'qualify',execute=forbidden,restore=forbidden,probe=forbidden,inspect=forbidden)
            self.assertEqual(result['status'],'nonpublishing-findings-gate-qualified')
            self.assertEqual(result['verdict']['status'],'blocked')
            for key in ('authorization','publicationReady','findingsAccepted'):self.assertFalse(result[key])
            self.assertEqual(result['review']['kind'],'nonpublishing-findings-gate-qualification')
            with self.assertRaises(ValueError):pub.consume(self.bundle,self.case.policy_path,'publish',execute=forbidden,inspect=forbidden)

    def test_missing_or_changed_review_blocks_qualification(self):
        root=self.case.case.root;(root/'.github').mkdir();(root/'.github/CODEOWNERS').write_text('* @human\n')
        self.files={'.github/CODEOWNERS':root/'.github/CODEOWNERS'}
        with patch.dict(os.environ,self.env),patch.object(pub,'RISK_POLICY_FILES',tuple(self.files)),patch.object(pub.native,'api',side_effect=self.api):
            self.state('qualify');self.reviews=[]
            with self.assertRaises(ValueError):pub.consume(self.bundle,self.case.policy_path,'qualify')
            self.bundle.pop('_riskAcceptance',None);self.reviews=self.case.api('actions/runs/123/approvals')
            self.state('qualify');self.case.findings[0]['version']='changed'
            self.bundle=self.case.bundle();self.bundle['normalizedFindings']=[dict(identity='x',severity='High')]
            with self.assertRaises(ValueError):pub.consume(self.bundle,self.case.policy_path,'qualify')

    def test_manual_qualification_cannot_reach_either_writer_or_writer_credentials(self):
        import subprocess
        data=json.loads(subprocess.run(['yq','-o=json','.',str(fixture.ROOT/'.github/workflows/publication.yml')],
            capture_output=True,text=True,check=True,timeout=10).stdout)
        self.assertFalse(data['on']['workflow_dispatch']['inputs']['native_qualification_only']['default'])
        self.assertIn('maestro-publication-qualification',data['concurrency']['group'])
        self.assertIn("|| 'maestro-publication'",data['concurrency']['group'])
        for name in ('publish','native_publish'):
            self.assertIn('inputs.native_qualification_only != true',data['jobs'][name]['if'])
        job=data['jobs']['native_qualify'];encoded=json.dumps(job)
        self.assertIn('inputs.native_qualification_only == true',job['if'])
        self.assertIn("github.event_name == 'workflow_dispatch'",job['if'])
        self.assertIn("github.ref == 'refs/heads/main'",job['if'])
        self.assertEqual(job['needs'],'native_review');self.assertEqual(job['environment']['name'],risk.ENVIRONMENT)
        self.assertEqual(set(job['permissions'].values()),{'read'})
        for forbidden in ('secrets.','CACHIX','DECIDER','release:native:publish','ci:native:publication'):
            self.assertNotIn(forbidden,encoded)
        self.assertIn('ci:native:qualify',encoded)

    def test_literal_tasks_and_exact_production_queue_match_repository_contract(self):
        import subprocess,re
        path=fixture.ROOT/'.github/workflows/publication.yml'
        data=json.loads(subprocess.run(['yq','-o=json','.',str(path)],capture_output=True,text=True,check=True,timeout=10).stdout)
        contract=json.loads((fixture.ROOT/'modules/ci/checks/_lib/repository-rules.json').read_text())
        rule=next(r for r in contract if r['path']=='.github/workflows/publication.yml' and 'production queue' in r['message'])
        self.assertIn(rule['needle'],path.read_text())
        self.assertNotIn(rule['needle'],path.read_text().replace("|| 'maestro-publication'","|| 'wrong-production-queue'"))
        pattern=r"nix run --accept-flake-config \.#devenv -- tasks run --mode single .* [a-z0-9:_-]+"
        for job in data['jobs'].values():
            for step in job['steps']:
                if 'run' in step:
                    self.assertRegex(step['run'],'^'+pattern+'$')
                    self.assertIn("--option 'packages:pkgs!' ''",step['run'])
        self.assertIsNone(re.fullmatch(pattern,"nix run --accept-flake-config .#devenv -- tasks run --mode single --option 'packages:pkgs!' '' \"${TASK}\""))
        pre=data['jobs']['native_review']
        retained=next(s for s in pre['steps'] if s.get('uses','').startswith('actions/upload-artifact@'))
        self.assertEqual(retained['if'],'always()')
        self.assertIn('native-findings-diagnostic.json',retained['with']['path'])
        for step in pre['steps']:
            if step.get('id') in ('review','qualification_review'):
                self.assertEqual(step['env']['NATIVE_RESULT_FILE'],'${{ runner.temp }}/native-findings-diagnostic.json')
        selection={step['id']:step for step in pre['steps'] if step.get('id') in ('review','qualification_review')}
        self.assertIn('inputs.native_qualification_only == true',selection['qualification_review']['if'])
        self.assertTrue(selection['qualification_review']['run'].endswith('ci:native:review-qualification'))
        self.assertIn('steps.qualification_review.outputs.context_sha256',pre['outputs']['context_sha256'])

    def test_real_review_cli_retains_bounded_context_and_summary_without_authority(self):
        import subprocess,sys,tempfile
        with tempfile.TemporaryDirectory() as directory:
            driver="""import importlib.util,sys,os,json
from pathlib import Path
from unittest.mock import patch
from contextlib import contextmanager
spec=importlib.util.spec_from_file_location('fixture',sys.argv[1]);f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
c=f.Risk();c.setUp();root=c.case.case.root
(root/'.github').mkdir();(root/'.github/CODEOWNERS').write_text('* @human\\n')
c.files={'.github/CODEOWNERS':root/'.github/CODEOWNERS'}
c.bundle['normalizedFindings'][0]['largeExposure']='x'*(2*1024**2)
@contextmanager
def selected(*a,**k):yield c.bundle
out=Path(sys.argv[2]);mode=sys.argv[3] if len(sys.argv)>3 else ''
if len(sys.argv)>3 and sys.argv[3]=='cap':f.pub.MAX_REVIEW_BYTES=1024
if len(sys.argv)>3 and sys.argv[3]=='exists':(out/'review.json').write_text('sentinel')
env=dict(c.env,MAESTRO_NATIVE_SECURITY_POLICY=str(c.case.policy_path),NATIVE_RISK_REVIEW_FILE=str(out/'review.json'),GITHUB_OUTPUT=str(out/'outputs'),GITHUB_STEP_SUMMARY=str(out/'summary'))
sys.argv=['native-publication','review','--run','7','--attempt','1','--revision','a'*40]
if mode=='release':
 c.bundle['receipt'].update(runAttempt=1,bootOrigin=dict(runId=8,runAttempt=2,revision='b'*40))
 original_api=c.api
 def release_api(path):
  if path=='actions/runs/123':return dict(original_api(path),path=f.risk.WORKFLOWS['release'])
  if path.startswith('contents/VERSION?ref='):return dict(encoding='base64',size=6,content='My4yLjAK')
  if path.startswith('actions/runs/8/artifacts?'):return dict(artifacts=[dict(id=50,name='maestro-installer',size_in_bytes=100,digest='sha256:'+'c'*64,expired=False,expires_at='2099-01-01T00:00:00Z',workflow_run=dict(id=8,head_sha='b'*40,head_branch='main'))])
  return original_api(path)
 c.api=release_api;sys.argv+=['--review-operation','release']
with patch.dict(os.environ,env),patch.object(f.pub,'RISK_POLICY_FILES',tuple(c.files)),patch.object(f.pub.native,'api',side_effect=c.api),patch.object(f.pub,'selected',selected):f.pub.main()
c.doCleanups()
"""
            result=subprocess.run([sys.executable,'-c',driver,str(Path(__file__)),directory],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            value=json.loads((Path(directory)/'review.json').read_text())
            self.assertFalse(value['authorization']);self.assertEqual(value['verdict']['status'],'blocked')
            self.assertGreater((Path(directory)/'review.json').stat().st_size,1024**2)
            self.assertEqual((Path(directory)/'outputs').read_text().strip(),'context_sha256='+value['review']['contextSha256'])
            self.assertIn('including high/critical',(Path(directory)/'summary').read_text())
            released=Path(directory)/'release';released.mkdir()
            result=subprocess.run([sys.executable,'-c',driver,str(Path(__file__)),str(released),'release'],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            outputs=dict(line.split('=',1) for line in (released/'outputs').read_text().splitlines())
            self.assertEqual(outputs['release_version'],'3.2.0');self.assertEqual(outputs['media_artifact_id'],'50')
            self.assertEqual((outputs['media_run'],outputs['media_attempt'],outputs['media_revision']),('8','2','b'*40))
            review=json.loads((released/'review.json').read_text());self.assertFalse(review['authorization'])
            self.assertEqual(review['review']['context']['operation'],'release')
            for flag in ('cap','exists'):
                child=Path(directory)/flag;child.mkdir()
                failed=subprocess.run([sys.executable,'-c',driver,str(Path(__file__)),str(child),flag],capture_output=True,text=True,timeout=20)
                self.assertNotEqual(failed.returncode,0)
                self.assertFalse((child/'outputs').exists())
                if flag=='cap':self.assertFalse((child/'review.json').exists())
                else:self.assertEqual((child/'review.json').read_text(),'sentinel')

    def test_real_consumer_accepts_exact_risk_but_stops_before_write_on_access_loss(self):
        root=self.case.case.root;(root/'.github').mkdir();(root/'.github/CODEOWNERS').write_text('* @human\n')
        self.files={'.github/CODEOWNERS':root/'.github/CODEOWNERS'}
        scope=pub.native.common.cache_publication.closure(self.bundle['product']);calls=[]
        def restore(*args,**kwargs):
            kwargs['closure_metadata'].write_text(json.dumps(scope));self.permission['permission']='read'
        with patch.dict(os.environ,self.env),patch.object(pub,'RISK_POLICY_FILES',tuple(self.files)),patch.object(pub.native,'api',side_effect=self.api):
            self.state()
            with self.assertRaises(ValueError):pub.consume(self.bundle,self.case.policy_path,'publish',transport=Path('/fixture'),
                inspect=lambda *a:dict(status='partial',missing=[next(iter(scope))]),restore=restore,query=lambda p:scope,
                execute=lambda *a,**k:calls.append('write'),probe=lambda *a:dict(status='verified'))
        self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
