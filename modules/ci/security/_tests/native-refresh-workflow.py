#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Manual-only refresh uses ordinary read/sign/report jobs, never publication."""
import json
from pathlib import Path
import subprocess
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
        self.assertEqual(job['timeout-minutes'],data['jobs']['dependencies']['timeout-minutes'])
        self.assertEqual(job['permissions'],{'contents':'read','actions':'read','attestations':'write',
            'id-token':'write','artifact-metadata':'write'})
        for name in ('dependencies','release_candidates'):self.assertIn('inputs.native_refresh != true',data['jobs'][name]['if'])
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

    def test_both_consumers_keep_disabled_activation_and_exact_health_pair(self):
        for filename,name in [('publication.yml','native_publish'),('consumer-probe.yml','native_consumer')]:
            data=workflow(filename)
            # Locate by command rather than depending on presentation job IDs.
            jobs=[j for key,j in data['jobs'].items() if key==name and "vars.MAESTRO_NATIVE_PUBLICATION_ENABLED == 'true'" in j.get('if','')]
            self.assertEqual(len(jobs),1);job=jobs[0]
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
