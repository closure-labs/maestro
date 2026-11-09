#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native-only release routing, signer identity, and bounded real CLI outputs."""
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
        data=workflow('release.yml')
        self.assertFalse(data['on']['workflow_dispatch']['inputs']['native_release']['default'])
        self.assertEqual(set(data['jobs']), {'native_review','native_finalize','native_qualification_review','native_qualification'})
        for name in ('release-publication.yml','release-continuation.yml'):
            self.assertFalse((ROOT/'.github/workflows'/name).exists())
        for enabled,native,expected_review in [('false',False,False),('false',True,False),('true',True,True),('true',False,False)]:
            values={'vars.MAESTRO_NATIVE_RELEASE_ENABLED':enabled,'inputs.native_release':native,'inputs.native_release_qualification_only':False,
                'github.event_name':'workflow_dispatch','github.repository':'closure-labs/maestro','github.ref':'refs/heads/main',
                'inputs.native_run':'7','inputs.native_revision':'a'*40}
            expression=' '.join(data['jobs']['native_review']['if'].split())
            expression=re.sub(r'(?:vars|inputs|github)\.[A-Za-z0-9_.]+',lambda m:repr(values[m.group()]),expression)
            expression=expression.replace('&&',' and ').replace('||',' or ').replace('true','True').replace('false','False')
            with self.subTest(enabled=enabled,native=native):
                self.assertEqual(eval(expression,{'__builtins__':{}}),expected_review)

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
        self.assertNotIn('workflow_call',data['on'])
        for forbidden in ('secrets.','DECIDER','CACHIX','ci:decision:','release:retain','ci:security:scan','nix copy'):
            self.assertNotIn(forbidden,json.dumps(job))
        self.assertEqual(data['concurrency']['group'],"${{ inputs.native_release_qualification_only == true && format('maestro-release-qualification-{0}', github.run_id) || 'maestro-release' }}")
        self.assertEqual(job['concurrency'],dict(group='maestro-publication',queue='max',**{'cancel-in-progress':False}))
        script=(ROOT/'modules/release/publication/_source/release-attestations.sh').read_text()
        self.assertIn('--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',script)

    def test_retired_reusable_controller_has_no_active_callers(self):
        self.assertNotIn('workflow_call',workflow('release.yml')['on'])
        for path in (ROOT/'.github/workflows').glob('*.yml'):
            for job in workflow(path.name)['jobs'].values():
                self.assertNotIn(job.get('uses'), ('$/.github/workflows/release.yml','./.github/workflows/release.yml'))

    def test_native_direct_route_cannot_start_legacy_version_or_packet_jobs(self):
        data=workflow('release.yml')
        for name in ('prepare','context','security','release'):
            self.assertNotIn(name,data['jobs'])
        for name in ('bump','event_continuation','release_request_run_id','release_candidate_run_id'):
            self.assertNotIn(name,data['on']['workflow_dispatch']['inputs'])
        for enabled,native in [('false',False),('false',True),('true',False),('true',True)]:
            for reviewed in ('success','failure','skipped'):
                values={'vars.MAESTRO_NATIVE_RELEASE_ENABLED':enabled,'inputs.native_release':native,'inputs.native_release_qualification_only':False,
                    'github.event_name':'workflow_dispatch','github.repository':'closure-labs/maestro','github.ref':'refs/heads/main',
                    'needs.native_review.result':reviewed}
                expression=' '.join(data['jobs']['native_finalize']['if'].split())
                expression=re.sub(r'(?:vars|inputs|github|needs)\.[A-Za-z0-9_.]+',lambda m:repr(values[m.group()]),expression)
                expression=expression.replace('&&',' and ').replace('||',' or ').replace('true','True').replace('false','False')
                with self.subTest(enabled=enabled,native=native,reviewed=reviewed):
                    self.assertEqual(eval(expression,{'__builtins__':{}}),enabled=='true' and native is True and reviewed=='success')

    def test_one_exact_media_download_stage_attestation_and_writer_sequence(self):
        job=workflow('release.yml')['jobs']['native_finalize'];steps=job['steps']
        download=next(i for i,s in enumerate(steps) if s.get('uses','').startswith('actions/download-artifact@'))
        stage=next(i for i,s in enumerate(steps) if s.get('run','').endswith('release:native:stage-reviewed'))
        writer=next(i for i,s in enumerate(steps) if s.get('run','').endswith('release:native:publish'))
        attest=[i for i,s in enumerate(steps) if s.get('uses','').startswith('actions/attest@')]
        self.assertEqual(len(attest),3);self.assertTrue(download<stage<min(attest)<writer)
        self.assertEqual(steps[download]['with']['artifact-ids'],'${{ needs.native_review.outputs.media_artifact_id }}')
        self.assertEqual(steps[download]['with']['run-id'],'${{ needs.native_review.outputs.media_run }}')
        self.assertNotIn('NATIVE_DIRECTORY',steps[stage].get('env',{}))
        self.assertEqual(steps[writer]['env']['NATIVE_DIRECTORY'],'${{ runner.temp }}/native-candidate')
        self.assertIn('/native-health',steps[writer]['env']['NATIVE_HEALTH_DIRECTORY'])
        self.assertEqual(steps[attest[1]]['with']['sbom-path'],'${{ runner.temp }}/native-candidate/maestro-system.spdx.json')
        self.assertEqual(steps[attest[0]]['with']['subject-path'],steps[writer]['env']['NATIVE_RELEASE_ISO'])
        self.assertEqual(steps[attest[2]]['with'],{'subject-path':'${{ runner.temp }}/native-release-assets/native-release-staging.json'})
        self.assertTrue(attest[1]<attest[2]<writer)

    def test_qualification_excludes_all_production_jobs_and_has_no_public_writer(self):
        data=workflow('release.yml');jobs=data['jobs']
        self.assertFalse(data['on']['workflow_dispatch']['inputs']['native_release_qualification_only']['default'])
        for name,job in jobs.items():
            if name not in ('native_qualification_review','native_qualification'):
                self.assertIn('inputs.native_release_qualification_only != true',job['if'])
        for name in ('native_qualification_review','native_qualification'):
            job=jobs[name];raw=json.dumps(job)
            self.assertIn('inputs.native_release_qualification_only == true',job['if'])
            self.assertIn('inputs.native_release != true',job['if'])
            for forbidden in ('MAESTRO_NATIVE_RELEASE_ENABLED','secrets.','DECIDER','CACHIX',
                'release:native:publish','release:native:stage-reviewed','ci:decision:',
                'create-github-app-token','maestro-publication'):
                self.assertNotIn(forbidden,raw)
            self.assertEqual(job['permissions']['contents'],'read')
        preflight=jobs['native_qualification_review']
        self.assertEqual(set(preflight['permissions'].values()),{'read'})
        job=jobs['native_qualification'];steps=job['steps']
        self.assertEqual(job['permissions'],{'actions':'read','contents':'read','attestations':'write','artifact-metadata':'write','id-token':'write'})
        self.assertEqual(job['environment']['name'],'findings-risk-review')
        self.assertEqual(job['needs'],'native_qualification_review')
        stage=next(i for i,s in enumerate(steps) if s.get('run','').endswith('release:native:stage-qualification'))
        attest=[i for i,s in enumerate(steps) if s.get('uses','').startswith('actions/attest@')]
        verify=next(i for i,s in enumerate(steps) if s.get('run','').endswith('release:native:verify-qualification'))
        self.assertEqual(len(attest),2);self.assertTrue(stage<min(attest)<max(attest)<verify)
        self.assertEqual(steps[attest[0]]['with']['subject-path'],steps[attest[1]]['with']['subject-path'])
        self.assertIn('/native-candidate/',steps[attest[1]]['with']['sbom-path'])
        # Upload only small receipts, never qualification media/parts or a release packet.
        upload=steps[-1]['with'];self.assertEqual(upload['name'],'maestro-native-release-qualification')
        self.assertNotIn('*.iso',upload['path']);self.assertNotIn('prepared',upload['path'])

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
