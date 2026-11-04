#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive native release routing, signer identity, and bounded real CLI outputs."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[4]


def workflow(name):
    return json.loads(subprocess.run(['yq','-o=json','.',str(ROOT/'.github/workflows'/name)],
        capture_output=True,text=True,check=True,timeout=10).stdout)


class ReleaseWorkflow(unittest.TestCase):
    def test_default_off_direct_native_route_cannot_fall_back_to_version_mutation(self):
        data=workflow('release.yml');legacy=workflow('release-publication.yml')
        self.assertFalse(data['on']['workflow_dispatch']['inputs']['native_release']['default'])
        self.assertNotIn('native_release',legacy['on']['workflow_dispatch']['inputs'])
        self.assertNotIn('native_publish',legacy['jobs'])
        for enabled,native,expected_prepare,expected_review in [('false',False,True,False),
            ('false',True,False,False),('true',True,False,True),('true',False,False,False)]:
            values={'vars.MAESTRO_NATIVE_RELEASE_ENABLED':enabled,'inputs.native_release':native,
                'github.event_name':'workflow_dispatch','github.repository':'closure-labs/maestro','github.ref':'refs/heads/main',
                'inputs.native_run':'7','inputs.native_revision':'a'*40,'inputs.release_request_run_id':'','inputs.release_candidate_run_id':''}
            def check(name):
                expression=' '.join(data['jobs'][name]['if'].split())
                expression=re.sub(r'(?:vars|inputs|github)\.[A-Za-z0-9_.]+',lambda m:repr(values[m.group()]),expression)
                expression=expression.replace('&&',' and ').replace('||',' or ').replace('true','True').replace('false','False')
                return eval(expression,{'__builtins__':{}})
            with self.subTest(enabled=enabled,native=native):
                self.assertEqual(check('prepare'),expected_prepare);self.assertEqual(check('native_review'),expected_review)

    def test_preflight_has_no_writer_secret_and_exports_proof_derived_media(self):
        job=workflow('release.yml')['jobs']['native_review']
        self.assertEqual(set(job['permissions'].values()),{'read'})
        self.assertNotIn('environment',job)
        for forbidden in ('secrets.','CACHIX','DECIDER','ci:decision:','create-github-app-token'):
            self.assertNotIn(forbidden,json.dumps(job))
        step=next(s for s in job['steps'] if s.get('id')=='review')
        self.assertTrue(step['run'].endswith('release:native:review'))
        for name in ('context_sha256','version','media_artifact_id','media_run','media_attempt','media_revision'):
            self.assertIn('steps.review.outputs.',job['outputs'][name])

    def test_direct_jobs_preserve_least_privilege_signer_and_original_key_contract(self):
        data=workflow('release.yml');job=data['jobs']['native_finalize']
        self.assertNotIn('uses',job);self.assertNotIn('uses',data['jobs']['native_review'])
        self.assertEqual(job['needs'],'native_review')
        self.assertIn("needs.native_review.result == 'success'",job['if'])
        self.assertEqual(job['environment']['name'],'findings-risk-review')
        self.assertEqual(job['permissions'],{'contents':'write','actions':'read','attestations':'write',
            'artifact-metadata':'write','id-token':'write'})
        self.assertTrue(data['on']['workflow_call']['secrets']['DECIDER_KEY']['required'])
        self.assertEqual(set(data['on']['workflow_call']['inputs']),{'release_request_run_id','release_candidate_run_id'})
        for forbidden in ('secrets.','DECIDER','CACHIX','ci:decision:','release:retain','ci:security:scan','nix copy'):
            self.assertNotIn(forbidden,json.dumps(job))
        self.assertEqual(data['concurrency']['group'],'maestro-release')
        self.assertEqual(job['concurrency'],dict(group='maestro-publication',queue='max',**{'cancel-in-progress':False}))
        script=(ROOT/'modules/release/publication/_source/release-attestations.sh').read_text()
        self.assertIn('--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',script)

    def test_reusable_permission_ceilings_include_every_job_even_when_skipped(self):
        data=workflow('release.yml');rank={'none':0,'read':1,'write':2};required={}
        for job in data['jobs'].values():
            for scope,level in job.get('permissions',data['permissions']).items():
                required[scope]=max(required.get(scope,0),rank[level])
        callers=[]
        for path in (ROOT/'.github/workflows').glob('*.yml'):
            for job in workflow(path.name)['jobs'].values():
                if job.get('uses') in ('$/.github/workflows/release.yml','./.github/workflows/release.yml'):
                    callers.append(job)
        self.assertEqual(len(callers),1)
        for caller in callers:
            for scope,level in required.items():
                self.assertGreaterEqual(rank[caller['permissions'].get(scope,'none')],level,scope)
        self.assertEqual(callers[0]['secrets']['DECIDER_KEY'],'${{ secrets.DECIDER_KEY }}')

    def test_native_direct_route_cannot_start_legacy_version_or_packet_jobs(self):
        data=workflow('release.yml')
        for enabled,native in [('false',False),('false',True),('true',False),('true',True)]:
            values={'vars.MAESTRO_NATIVE_RELEASE_ENABLED':enabled,'inputs.native_release':native,
                'github.event_name':'workflow_dispatch','github.repository':'closure-labs/maestro','github.ref':'refs/heads/main',
                'inputs.release_request_run_id':'','inputs.release_candidate_run_id':'',
                'needs.native_review.result':'success','needs.prepare.result':'success','inputs.event_continuation':False,
                'needs.prepare.outputs.restarted':'false'}
            def check(name):
                expression=' '.join(data['jobs'][name]['if'].split())
                expression=re.sub(r'(?:vars|inputs|github|needs)\.[A-Za-z0-9_.]+',lambda m:repr(values[m.group()]),expression)
                expression=expression.replace('!cancelled()','True').replace('&&',' and ').replace('||',' or ').replace('true','True').replace('false','False')
                return eval(expression,{'__builtins__':{},'contains':lambda xs,x:x in xs,'fromJSON':json.loads})
            with self.subTest(enabled=enabled,native=native):
                self.assertEqual(check('prepare'),enabled=='false' and native is False)
                self.assertEqual(check('context'),enabled=='false' and native is False)
                self.assertEqual(check('native_finalize'),enabled=='true' and native is True)
                values['needs.native_review.result']='failure';self.assertFalse(check('native_finalize'))
        self.assertIn("vars.MAESTRO_NATIVE_RELEASE_ENABLED != 'true'",workflow('release-continuation.yml')['jobs']['resolve']['if'])

    def test_one_exact_media_download_stage_attestation_and_writer_sequence(self):
        job=workflow('release.yml')['jobs']['native_finalize'];steps=job['steps']
        download=next(i for i,s in enumerate(steps) if s.get('uses','').startswith('actions/download-artifact@'))
        stage=next(i for i,s in enumerate(steps) if s.get('run','').endswith('release:native:stage-reviewed'))
        writer=next(i for i,s in enumerate(steps) if s.get('run','').endswith('release:native:publish'))
        attest=[i for i,s in enumerate(steps) if s.get('uses','').startswith('actions/attest@')]
        self.assertEqual(len(attest),2);self.assertTrue(download<stage<min(attest)<writer)
        self.assertEqual(steps[download]['with']['artifact-ids'],'${{ needs.native_review.outputs.media_artifact_id }}')
        self.assertEqual(steps[download]['with']['run-id'],'${{ needs.native_review.outputs.media_run }}')
        self.assertNotIn('NATIVE_DIRECTORY',steps[stage].get('env',{}))
        self.assertEqual(steps[writer]['env']['NATIVE_DIRECTORY'],'${{ runner.temp }}/native-candidate')
        self.assertIn('/native-health',steps[writer]['env']['NATIVE_HEALTH_DIRECTORY'])
        self.assertEqual(steps[attest[1]]['with']['sbom-path'],'${{ runner.temp }}/native-candidate/maestro-system.spdx.json')
        self.assertEqual(steps[attest[0]]['with']['subject-path'],steps[writer]['env']['NATIVE_RELEASE_ISO'])

    def test_real_stage_wrapper_allows_verified_auto_staging_and_preserves_health_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'arguments.py';source.write_text('import sys,json; print(json.dumps(sys.argv[1:]))')
            env=dict(os.environ,MAESTRO_NATIVE_RELEASE_STAGE_SOURCE=str(source),NATIVE_ISO='input.iso',NATIVE_RELEASE_OUTPUT='output',
                NATIVE_RELEASE_VERSION='3.2.0',NATIVE_RUN='7',NATIVE_ATTEMPT='1',NATIVE_REVISION='a'*40,
                NATIVE_MEDIA_RUN='8',NATIVE_MEDIA_ATTEMPT='2',NATIVE_MEDIA_REVISION='b'*40,NATIVE_DIRECTORY='')
            path=ROOT/'modules/release/publication/_source/native-release-stage.sh'
            result=subprocess.run(['bash',str(path),'--findings-review'],env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);args=json.loads(result.stdout)
            self.assertNotIn('--directory',args);self.assertIn('--findings-review',args)
            path=ROOT/'modules/ci/security/_source/native-publication.sh'
            env.update(MAESTRO_NATIVE_PUBLICATION_SOURCE=str(source),NATIVE_HEALTH_RUN='20',NATIVE_HEALTH_ATTEMPT='1',NATIVE_HEALTH_DIRECTORY='fresh')
            result=subprocess.run(['bash',str(path),'check'],env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);args=json.loads(result.stdout)
            self.assertEqual(args[args.index('--health-directory')+1],'fresh')
            env['NATIVE_HEALTH_RUN']=''
            result=subprocess.run(['bash',str(path),'check'],env=env,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)


if __name__=='__main__':unittest.main()
