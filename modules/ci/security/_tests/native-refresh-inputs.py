#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Historical input identity is never a current-health/publication capability."""
from copy import deepcopy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('prepare_fixture',Path(__file__).with_name('native-prepare.py'))
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)

DRIVER='''import importlib.util,json,os,sys
from pathlib import Path
source=Path(os.environ['NATIVE_SOURCE'])
spec=importlib.util.spec_from_file_location('prepare',source);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
try:
 origin=json.loads(os.environ['BOOT_ORIGIN']);origin=None if origin is None else tuple(origin)
 with p.verified_inventory(Path(os.environ['NATIVE_FIXTURE_BUNDLE']),7,1,'a'*40,Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY']),origin) as bundle:
  if os.environ['TRY_PUBLICATION']=='true':
   spec=importlib.util.spec_from_file_location('publication',source.with_name('native-publication.py'));pub=importlib.util.module_from_spec(spec);spec.loader.exec_module(pub)
   pub.consume(bundle,Path(os.environ['MAESTRO_NATIVE_PREPARE_POLICY']),'check')
  print(json.dumps(bundle['receipt']))
except Exception as error:
 print(type(error).__name__+': '+str(error),file=sys.stderr);sys.exit(2)
'''

class RefreshInputs(unittest.TestCase):
    def setUp(self):
        self.case=fixture.NativePrepare();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.driver=self.case.root/'driver.py';self.driver.write_text(DRIVER)
        (self.case.bundle/'Cargo.lock').write_text('original immutable lockfile fixture')
        inputs={name:fixture.prepare.file_hash(self.case.bundle/name) for name in ('maestro-system.cdx.json','xen-orchestra-supply.cdx.json','Cargo.lock')}
        path=self.case.bundle/'inputs.sha256';path.write_text(''.join(digest+'  /original/inventory/'+name+'\n' for name,digest in inputs.items()))
        system=self.case.bundle/'maestro-system.cdx.json'
        self.case.native['evidence']=dict(inputHashes=dict(sha256=fixture.prepare.file_hash(path),size=path.stat().st_size),
            inventory=dict(sha256=fixture.prepare.file_hash(system),size=system.stat().st_size))
    def expired(self):
        scanned=dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=3)
        self.case.native['scannedAt']=scanned.isoformat();self.case.native['database']['built']=(scanned-dt.timedelta(hours=1)).isoformat()
        self.case.scans.update(scannedAt=scanned.isoformat(),expiresAt=(scanned+dt.timedelta(hours=24)).isoformat())
    def run_identity(self,publication=False,write=True):
        if write:self.case.write_bundle()
        state=self.case.root/'state.json';state.write_text(json.dumps(self.case.state))
        env=dict(os.environ,PATH=str(self.case.bin)+os.pathsep+os.environ['PATH'],PYTHONDONTWRITEBYTECODE='1',
            NATIVE_SOURCE=str(ROOT/'modules/ci/security/_source/native-prepare.py'),TRY_PUBLICATION=str(publication).lower(),
            MAESTRO_NATIVE_PREPARE_POLICY=str(self.case.policy),NATIVE_FIXTURE_STATE=str(state),
            NATIVE_FIXTURE_CALLS=str(self.case.calls),NATIVE_FIXTURE_BUNDLE=str(self.case.bundle),BOOT_ORIGIN=json.dumps(self.case.boot_origin))
        def cap():resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
        return subprocess.run([sys.executable,str(self.driver)],env=env,capture_output=True,text=True,timeout=30,preexec_fn=cap)
    def test_expired_identity_requires_authentic_complete_inputs_but_is_not_health(self):
        self.expired();r=self.run_identity();self.assertEqual(r.returncode,0,r.stderr)
        receipt=json.loads(r.stdout);self.assertFalse(receipt['currentHealthVerified'])
        for key in ('authorization','publicationReady','riskAcceptanceEvaluated','isoBytesVerified','narBytesVerified'):self.assertFalse(receipt[key])
        self.assertEqual(receipt['status'],'verified-inventory-for-refresh')
        self.case.blocked() # The current-health CLI still rejects those bytes.
    def test_even_unexpired_inventory_context_cannot_enter_publication(self):
        r=self.run_identity(publication=True);self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertIn('Inventory identity is not current publication health',r.stderr)
    def test_database_must_have_been_valid_and_fresh_at_original_scan(self):
        self.expired();original=deepcopy(self.case.native)
        for patch in [dict(database=dict(valid=False,built=original['database']['built'])),
                      dict(database=dict(valid=True,built='2000-01-01T00:00:00Z')),dict(scannerHealth='failed'),dict(scannedAt='2099-01-01T00:00:00Z')]:
            self.case.native={**deepcopy(original),**patch}
            r=self.run_identity();self.assertEqual(r.returncode,2,r.stdout+r.stderr)
    def test_bad_envelope_proof_documents_scope_and_main_reject(self):
        self.expired();original=deepcopy(self.case.scans)
        self.case.scans['expiresAt']=self.case.scans['scannedAt'];self.assertEqual(self.run_identity().returncode,2)
        self.case.scans=original
        for flag in ('proofFailure','forgedSubject','mainAfter'):
            self.case.state[flag]='f'*40 if flag=='mainAfter' else True
            self.assertEqual(self.run_identity().returncode,2);self.case.state.pop(flag)
        self.case.write_bundle();(self.case.bundle/fixture.prepare.DOCUMENTS[0]).write_text('changed')
        self.assertEqual(self.run_identity(write=False).returncode,2)
    def test_all_validation_jobs_and_exact_retained_boot_still_required(self):
        self.expired();jobs=deepcopy(self.case.result['jobs']);self.case.result['jobs']['AUDIT_RESULT']='skipped'
        self.assertEqual(self.run_identity().returncode,2);self.case.result['jobs']=jobs
        self.case.retained();self.case.state['forgedOriginal']=True
        self.assertEqual(self.run_identity().returncode,2)
    def test_original_lockfile_and_checksum_identity_cannot_be_substituted(self):
        self.expired();self.case.write_bundle()
        for name in ('Cargo.lock','inputs.sha256'):
            path=self.case.bundle/name;old=path.read_bytes();path.write_bytes(b'forged')
            self.assertEqual(self.run_identity(write=False).returncode,2);path.write_bytes(old)
        self.case.native['evidence']['inventory']['sha256']='f'*64
        self.assertEqual(self.run_identity().returncode,2)

    def test_input_identity_does_not_need_or_create_a_risk_decision(self):
        self.expired();r=self.run_identity();self.assertEqual(r.returncode,0,r.stderr)
        calls=self.case.calls.read_text()
        self.assertNotIn('automation/',calls);self.assertNotIn('pulls/',calls)
        self.assertTrue(all(json.loads(line)[:3]==['api','--method','GET'] or json.loads(line)[:2]==['attestation','verify'] for line in calls.splitlines()))

if __name__=='__main__':unittest.main()
