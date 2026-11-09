#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native refresh preserves scheduled coverage without publication authority."""
import json
from pathlib import Path
import subprocess
import re
import unittest

ROOT=Path(__file__).resolve().parents[4]


def workflow(name):
    return json.loads(subprocess.run(['yq','-o=json','.',str(ROOT/'.github/workflows'/name)],
        check=True,capture_output=True,text=True,timeout=10).stdout)


class RefreshWorkflow(unittest.TestCase):
    def test_manual_exact_main_gate_no_writer_credentials_or_duplicate_rescan(self):
        data=workflow('security.yml');inputs=data['on']['workflow_dispatch']['inputs']
        self.assertFalse(inputs['native_refresh']['default'])
        job=data['jobs']['native_refresh']
        for guard in ("github.event_name == 'workflow_dispatch'","github.ref == 'refs/heads/main'",
                      "github.repository == 'closure-labs/maestro'",'inputs.native_refresh == true','inputs.policy_only != true'):
            self.assertIn(guard,job['if'])
        self.assertEqual(job['timeout-minutes'],45)
        self.assertEqual(job['permissions'],{'contents':'read','actions':'read','attestations':'write',
            'id-token':'write','artifact-metadata':'write'})
        for name in ('dependencies','release_candidates'):self.assertNotIn(name,data['jobs'])
        encoded=json.dumps(job)
        for forbidden in ('secrets.','DECIDER','CACHIX','ci:decision:','ci:native:publication','create-github-app-token'):
            self.assertNotIn(forbidden,encoded)
        runs=[s['run'] for s in job['steps'] if 'run' in s]
        self.assertEqual(len(runs),1);self.assertIn('ci:native:refresh',runs[0]);self.assertIn('devenv -- tasks run',runs[0])
        scan=next(s for s in job['steps'] if 'run' in s)
        self.assertEqual(scan['env']['NATIVE_REVISION'],'${{ inputs.native_revision || github.sha }}')
        self.assertEqual(scan['env']['NATIVE_POLICY_REVISION'],'${{ github.sha }}')
        self.assertEqual(inputs['native_revision']['default'],'')
        self.assertEqual(scan['env']['GH_TOKEN'],'${{ github.token }}')
        upload=next(s for s in job['steps'] if s.get('uses','').startswith('actions/upload-artifact@'))
        self.assertEqual(upload['with']['name'],'maestro-native-health');self.assertEqual(upload['with']['path'],'security-report')
        attest=next(s for s in job['steps'] if s.get('uses','').startswith('actions/attest@'))
        self.assertEqual(attest['with']['subject-path'],'security-report/native-health.json')

    def test_scheduled_native_route_retains_daily_coverage_without_activation_flag(self):
        data=workflow('security.yml');job=data['jobs']['native_refresh']
        self.assertIn("github.event_name == 'schedule'",job['if'])
        self.assertEqual(set(data['jobs']),{'native_refresh','native_official_refresh','policy'})
        self.assertNotIn('MAESTRO_NATIVE_REFRESH_ENABLED',json.dumps(data))
        step=next(s for s in job['steps'] if 'run' in s)
        self.assertEqual(step['env']['NATIVE_REFRESH_SELECT_CURRENT_MAIN'],"${{ github.event_name == 'schedule' && 'true' || 'false' }}")
        self.assertNotIn('MAESTRO_NATIVE_REFRESH_ENABLED =',(ROOT/'secretspec.toml').read_text())
        self.assertEqual(len(data['on']['schedule']),1)

    def test_schedule_routes_one_rolling_refresh_and_retains_official_product_coverage(self):
        data=workflow('security.yml')
        for event,enabled,native_input,policy_input,expected in [
            ('schedule','false',False,False,(False,True)),
            ('schedule','true',False,False,(False,True)),
            ('workflow_dispatch','false',True,False,(False,True)),
            ('workflow_dispatch','false',False,False,(True,False)),
            ('workflow_dispatch','true',True,True,(False,False))]:
            values={'github.event_name':event,'github.repository':'closure-labs/maestro',
                'github.ref':'refs/heads/main','vars.MAESTRO_NATIVE_REFRESH_ENABLED':enabled,
                'inputs.native_refresh':native_input,'inputs.policy_only':policy_input,'vars.MAESTRO_NATIVE_RELEASE_ENABLED':'false',
                'inputs.native_official_tag':'','inputs.native_official_publication_revision':''}
            def condition(name):
                expression=data['jobs'][name]['if']
                expression=re.sub(r'(?:github|vars|inputs)\.[A-Za-z_.]+',lambda m:repr(values[m.group()]),expression)
                expression=expression.replace('&&',' and ').replace('||',' or ').replace('true','True').replace('false','False')
                return eval(expression,{'__builtins__':{}})
            with self.subTest(event=event,enabled=enabled):
                self.assertEqual(condition('native_refresh'),expected[1])

    def test_official_refresh_is_explicit_keyless_and_never_falls_back_to_legacy(self):
        data=workflow('security.yml');inputs=data['on']['workflow_dispatch']['inputs']
        for name in ('native_official_tag','native_official_publication_revision'):self.assertEqual(inputs[name]['default'],'')
        job=data['jobs']['native_refresh'];self.assertNotIn('environment',job)
        self.assertEqual(job['permissions'],{'contents':'read','actions':'read','attestations':'write','id-token':'write','artifact-metadata':'write'})
        step=next(s for s in job['steps'] if 'run' in s)
        self.assertEqual(step['env']['NATIVE_OFFICIAL_RELEASE_TAG'],'${{ inputs.native_official_tag }}')
        self.assertEqual(step['env']['NATIVE_OFFICIAL_PUBLICATION_REVISION'],'${{ inputs.native_official_publication_revision }}')
        for forbidden in ('secrets.','ci:decision:','CACHIX','DECIDER'):
            self.assertNotIn(forbidden,json.dumps(job))

    def test_both_consumers_keep_disabled_activation_and_exact_health_pair(self):
        for filename,name in [('publication.yml','native_publish'),('consumer-probe.yml','native_consumer')]:
            data=workflow(filename)
            # Locate by command rather than depending on presentation job IDs.
            jobs=[j for key,j in data['jobs'].items() if key==name]
            self.assertEqual(len(jobs),1);job=jobs[0]
            if name=='native_publish':self.assertIn("vars.MAESTRO_NATIVE_PUBLICATION_ENABLED == 'true'",job['if'])
            else:self.assertNotIn('secrets.',json.dumps(job))
            self.assertIn("github.ref == 'refs/heads/main'",job['if'])
            self.assertIn("github.event_name == 'workflow_dispatch'",job['if'])
            step=next(s for s in job['steps'] if 'NATIVE_RUN' in s.get('env',{}))
            self.assertEqual(step['env']['NATIVE_REVISION'],'${{ inputs.native_revision }}')
            self.assertEqual(step['env']['NATIVE_POLICY_REVISION'],'${{ github.sha }}')
            self.assertNotIn('MAESTRO_NATIVE_RELEASE_ENABLED',step['env'])
            self.assertEqual(step['env']['NATIVE_HEALTH_RUN'],'${{ inputs.native_health_run }}')
            self.assertEqual(step['env']['NATIVE_HEALTH_ATTEMPT'],'${{ inputs.native_health_attempt }}')
            self.assertEqual(data['on']['workflow_dispatch']['inputs']['native_health_run']['default'],'')


if __name__=='__main__':unittest.main()
