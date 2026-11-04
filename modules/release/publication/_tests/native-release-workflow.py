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
    def test_default_off_native_selection_never_falls_back_to_legacy(self):
        data=workflow('release-publication.yml')
        self.assertFalse(data['on']['workflow_dispatch']['inputs']['native_release']['default'])
        for enabled,native,event,legacy,review in [('false',False,'schedule',True,False),
            ('false',False,'workflow_dispatch',True,False),('false',True,'workflow_dispatch',False,False),
            ('true',True,'workflow_dispatch',False,True),('true',False,'schedule',False,False)]:
            values={'vars.MAESTRO_NATIVE_RELEASE_ENABLED':enabled,'inputs.native_release':native,
                'github.event_name':event,'github.repository':'closure-labs/maestro','github.ref':'refs/heads/main',
                'inputs.native_run':'7','inputs.native_revision':'a'*40,'inputs.candidate_run':'','inputs.transaction_trial':'default'}
            def check(name):
                expression=data['jobs'][name]['if']
                expression=re.sub(r'(?:vars|inputs|github)\.[A-Za-z0-9_.]+',lambda m:repr(values[m.group()]),expression)
                expression=expression.replace('&&',' and ').replace('||',' or ').replace('true','True').replace('false','False')
                return eval(expression,{'__builtins__':{}})
            with self.subTest(enabled=enabled,native=native,event=event):
                self.assertEqual(check('publish'),legacy)
                self.assertEqual(check('native_review'),review)

    def test_preflight_has_no_writer_secret_and_exports_proof_derived_media(self):
        job=workflow('release-publication.yml')['jobs']['native_review']
        self.assertEqual(set(job['permissions'].values()),{'read'})
        self.assertNotIn('environment',job)
        encoded=json.dumps(job)
        for forbidden in ('secrets.','CACHIX','DECIDER','ci:decision:','create-github-app-token'):
            self.assertNotIn(forbidden,encoded)
        step=next(s for s in job['steps'] if s.get('id')=='review')
        self.assertTrue(step['run'].endswith('release:native:review'))
        for name in ('context_sha256','version','media_artifact_id','media_run','media_attempt','media_revision'):
            self.assertIn('steps.review.outputs.',job['outputs'][name])

    def test_reusable_signer_gate_permissions_and_legacy_isolation(self):
        parent=workflow('release-publication.yml');called=workflow('release.yml')
        caller=parent['jobs']['native_publish'];job=called['jobs']['native_finalize']
        self.assertEqual(caller['uses'],'$/.github/workflows/release.yml')
        self.assertEqual(caller['needs'],'native_review')
        self.assertIn("needs.native_review.result == 'success'",caller['if'])
        self.assertNotIn('secrets',caller)
        self.assertEqual(job['environment']['name'],'findings-risk-review')
        self.assertEqual(caller['permissions'],job['permissions'])
        self.assertEqual(job['permissions'],{'contents':'write','actions':'read','attestations':'write',
            'artifact-metadata':'write','id-token':'write'})
        self.assertFalse(called['on']['workflow_call']['secrets']['DECIDER_KEY']['required'])
        for name in ('prepare','context'):
            self.assertIn("vars.MAESTRO_NATIVE_RELEASE_ENABLED != 'true'",called['jobs'][name]['if'])
            self.assertIn('inputs.native_release != true',called['jobs'][name]['if'])
        self.assertIn("vars.MAESTRO_NATIVE_RELEASE_ENABLED != 'true'",workflow('release-continuation.yml')['jobs']['resolve']['if'])
        encoded=json.dumps(job)
        for forbidden in ('secrets.','DECIDER','CACHIX','ci:decision:','release:retain','ci:security:scan','nix copy'):
            self.assertNotIn(forbidden,encoded)
        self.assertEqual(parent['concurrency']['group'],'maestro-publication')
        self.assertEqual(called['concurrency']['group'],'maestro-release')
        script=(ROOT/'modules/release/publication/_source/release-attestations.sh').read_text()
        self.assertIn('--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',script)

    def test_native_reuse_cannot_start_legacy_version_mutation_or_packet_jobs(self):
        data=workflow('release.yml')
        for enabled,native in [('false',False),('false',True),('true',False),('true',True)]:
            values={'vars.MAESTRO_NATIVE_RELEASE_ENABLED':enabled,'inputs.native_release':native,
                'github.event_name':'workflow_dispatch','github.repository':'closure-labs/maestro','github.ref':'refs/heads/main',
                'inputs.native_context_sha256':'c'*64,'inputs.release_request_run_id':'','inputs.release_candidate_run_id':'',
                'needs.prepare.result':'success','inputs.event_continuation':False,'needs.prepare.outputs.restarted':'false'}
            def check(name):
                expression=' '.join(data['jobs'][name]['if'].split())
                expression=re.sub(r'(?:vars|inputs|github|needs)\.[A-Za-z0-9_.]+',lambda m:repr(values[m.group()]),expression)
                expression=expression.replace('!cancelled()','True').replace('&&',' and ').replace('||',' or ').replace('true','True').replace('false','False')
                return eval(expression,{'__builtins__':{},'contains':lambda xs,x:x in xs,'fromJSON':json.loads})
            with self.subTest(enabled=enabled,native=native):
                self.assertEqual(check('prepare'),enabled=='false' and native is False)
                self.assertEqual(check('context'),enabled=='false' and native is False)
                self.assertEqual(check('native_finalize'),enabled=='true' and native is True)
        self.assertEqual(workflow('release-continuation.yml')['jobs']['finalize']['secrets']['DECIDER_KEY'],'${{ secrets.DECIDER_KEY }}')

    def test_one_exact_media_download_stage_attestation_and_writer_sequence(self):
        job=workflow('release.yml')['jobs']['native_finalize'];steps=job['steps']
        download=next(i for i,s in enumerate(steps) if s.get('uses','').startswith('actions/download-artifact@'))
        stage=next(i for i,s in enumerate(steps) if s.get('run','').endswith('release:native:stage-reviewed'))
        writer=next(i for i,s in enumerate(steps) if s.get('run','').endswith('release:native:publish'))
        attest=[i for i,s in enumerate(steps) if s.get('uses','').startswith('actions/attest@')]
        self.assertEqual(len(attest),2);self.assertTrue(download<stage<min(attest)<writer)
        self.assertEqual(steps[download]['with']['artifact-ids'],'${{ inputs.native_media_artifact_id }}')
        self.assertEqual(steps[download]['with']['run-id'],'${{ inputs.native_media_run }}')
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
