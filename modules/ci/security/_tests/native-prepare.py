#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real bounded CLI fixtures for inactive native consumer preparation."""
import base64
from copy import deepcopy
import datetime as dt
import hashlib
import importlib.util
import json
import os
import resource
from unittest.mock import patch
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
SOURCE = ROOT / 'modules/ci/security/_source/native-prepare.py'
spec = importlib.util.spec_from_file_location('prepare', SOURCE)
prepare = importlib.util.module_from_spec(spec); spec.loader.exec_module(prepare)
SHA = 'a' * 40
NAR = 'sha256-' + 'A' * 43 + '='


class NativePrepare(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.bundle = self.root / 'bundle'; self.bundle.mkdir()
        self.bin = self.root / 'bin'; self.bin.mkdir(); self.calls = self.root / 'calls.jsonl'
        self.boot_origin = None; self.original = None
        self.cfg = json.loads((ROOT / prepare.POLICY).read_text())
        self.policy = self.root / 'policy.json'; self.policy.write_text(json.dumps(self.cfg))
        now = dt.datetime.now(dt.timezone.utc)
        paths = {name: '/nix/store/' + char * 32 + '-' + name for name, char in zip(
            ('appliance', *self.cfg['cachePublication']['roots']), 'abcdf')}
        self.subjects = [{'storePath': p, 'narHash': NAR} for p in paths.values()]
        context = {'schema': 2, 'tcpPorts': [], 'udpPorts': [], 'managementCIDRs': ['10.0.0.0/8'], 'ssh': {},
            'execution': {'xoUser': 'xo', 'User': 'xo', 'Group': 'xo'}, 'capabilities': [],
            'ambientCapabilities': [], 'helpers': {'enableNFS': False, 'enableCIFS': False,
            'enableVHD': False, 'fileRestore': False}, 'sudo': [], 'mountsDir': '/run/xo', 'installer': {
            'ssh': {}, 'firewall': {'allowedTCPPorts': [], 'allowedUDPPorts': [], 'extraCommands': ''},
            'sudo': {'enable': True, 'wheelNeedsPassword': False, 'extraRules': []},
            'operator': {'extraGroups': ['wheel'], 'passwordState': 'locked', 'rootPasswordState': 'locked', 'mutableUsers': True},
            'systemdInitrd': True, 'bootModes': {'bios': True, 'efi': True, 'memtest': True},
            'bootPolicy': {'kernelParams': [], 'emergencyMode': True, 'initrdEmergencyAccess': 'disabled'}}}
        self.native = {'status': 'complete', 'scannerHealth': 'healthy',
            'scannedAt': (now - dt.timedelta(minutes=5)).isoformat(),
            'database': {'valid': True, 'built': (now - dt.timedelta(hours=1)).isoformat()},
            'subjects': self.subjects, 'observations': [], 'securityContext': context,
            'coverage': {'contract': 'maestro-distribution-v2', 'manifest': {'roots': paths}}}
        producer = dict(workflow=prepare.WORKFLOW, signerWorkflow=prepare.WORKFLOW, revision=SHA, runId=7, runAttempt=1)
        self.scans = dict(schema=1, repository=prepare.REPO, revision=SHA, producer=producer,
            productProducer=deepcopy(producer), scannedAt=self.native['scannedAt'],
            expiresAt=(now + dt.timedelta(hours=1)).isoformat(), profiles={'maestro': self.native})
        self.product = dict(schema=1, repository=prepare.REPO, revision=SHA,
            products={'maestro': self.subjects[0]}, roots={name: dict(storePath=paths[name], narHash=NAR, profile='maestro')
                for name in self.cfg['cachePublication']['roots']}, assets={})
        prepare.common.cache_publication.attach(self.product, self.cfg,
            lambda selected: {p: {'narHash': NAR, 'references': []} for p in selected})
        self.binding = dict(schemaVersion=2, phase='inventory', transport=None, graphSha256='b' * 64,
            producer=dict(GITHUB_REPOSITORY=prepare.REPO, GITHUB_SHA=SHA, GITHUB_RUN_ID='7', GITHUB_RUN_ATTEMPT='1'),
            roots=self.subjects, targets=[{'outputs': {'out': p}} for p in paths.values()],
            isoSha256='c' * 64, evidenceFiles={})
        for name in prepare.DOCUMENTS:
            raw=('native fixture '+name).encode(); (self.bundle / name).write_bytes(raw)
            self.binding['evidenceFiles'][name]=hashlib.sha256(raw).hexdigest()
        self.result = dict(schemaVersion=1, producer=self.binding['producer'], completeValidationRequired=True,
            graphSha256='b' * 64, jobs={k:'success' for k in ('AUDIT_RESULT','COMPARISON_RESULT','SCAN_RESULT','QUALIFICATION_RESULT')},
            boot=dict(schemaVersion=1,producer=self.binding['producer'], disposition='executed', graphSha256='b'*64,
                isoSha256='c'*64, bootLogSha256='d'*64))
        self.state = {'main': SHA, 'policy': self.cfg, 'run': dict(id=7, run_attempt=1, head_sha=SHA,
            head_branch='main', repository={'full_name': prepare.REPO}, head_repository={'full_name': prepare.REPO},
            path=prepare.WORKFLOW, event='push', status='completed', conclusion='success')}
        fake=self.bin / 'gh'
        fake.write_text('#!'+sys.executable+'\n'+'''
import base64,hashlib,json,os,sys
from pathlib import Path
state=json.loads(Path(os.environ['NATIVE_FIXTURE_STATE']).read_text());args=sys.argv[1:]
if state.get('oversizedResponse'):
    sys.stdout.write('x' * (5 * 1024**2));sys.exit(0)
log=Path(os.environ['NATIVE_FIXTURE_CALLS']);previous=log.read_text().splitlines() if log.exists() else []
with log.open('a') as out:out.write(json.dumps(args)+'\\n')
if args[:3]==['api','--method','GET']:
    path=args[3];prefix='repos/closure-labs/maestro/'
    if path==prefix+'git/ref/heads/main':
        after=any('git/ref/heads/main' in row for row in previous)
        value={'object':{'sha':state.get('mainAfter',state['main']) if after else state['main']}}
    elif path==prefix+'contents/modules/ci/authority/_source/decision-policy.json?ref='+'a'*40:
        raw=json.dumps(state['policy']).encode();value={'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}
    elif path==prefix+'actions/runs/7/attempts/1':value=state['run']
    elif path==prefix+'actions/runs/8/attempts/2':value=state['originalRun']
    else:raise AssertionError('Unexpected endpoint/history/ledger/mutation: '+path)
    print(json.dumps(value))
elif args[:2]==['attestation','verify']:
    revision='b'*40 if Path(args[2]).name=='original-ci-result.json' else 'a'*40
    for flag,value in [('--repo','closure-labs/maestro'),('--signer-workflow','closure-labs/maestro/.github/workflows/ci.yml'),
                       ('--source-ref','refs/heads/main'),('--source-digest',revision),('--signer-digest',revision),('--format','json')]:
        assert args[args.index(flag)+1]==value
    assert '--deny-self-hosted-runners' in args
    assert Path(args[2]).parent != Path(os.environ['NATIVE_FIXTURE_BUNDLE']), 'Verify frozen bytes, not mutable originals'
    if state.get('proofFailure'):sys.exit(1)
    digest=hashlib.sha256(Path(args[2]).read_bytes()).hexdigest()
    if state.get('forgedSubject') or (state.get('forgedOriginal') and Path(args[2]).name=='original-ci-result.json'):digest='f'*64
    print(json.dumps([{'verificationResult':{'statement':{'subject':[{'digest':{'sha256':digest}}]}}}]))
else:raise AssertionError('Unexpected write/registry command')
'''); fake.chmod(0o700)

    def retained(self):
        self.boot_origin=(8,2,'b'*40)
        origin=prepare.origin_identity(*self.boot_origin)
        self.original_log=b'Reached target Multi-User System\n'
        boot=dict(self.result['boot'], producer=origin, origin=origin, graphSha256='d'*64,
            mediaInput='e'*64,verifierSha256='f'*64,bootLogSha256=hashlib.sha256(self.original_log).hexdigest())
        self.original=dict(schemaVersion=1,producer=origin,graphSha256='d'*64,boot=boot,
            completeValidationRequired=True,jobs=deepcopy(self.result['jobs']))
        self.result['boot'].update(disposition='verified-retained',origin=dict(runId=8,revision='b'*40),
            bootLogSha256=None,mediaInput='e'*64,verifierSha256='f'*64)
        self.binding['isoSha256']=None
        self.state['originalRun']={**deepcopy(self.state['run']), 'id':8,'run_attempt':2,'head_sha':'b'*40}
        self.write_bundle()
        self.result['inventoryIsoBinding']=dict(schemaVersion=1,producer=deepcopy(self.binding['producer']),
            inventorySha256=self.result['inventoryTransferSha256'],isoSha256=self.result['boot']['isoSha256'])

    def write_bundle(self):
        for name,value in (('product.json',self.product),('scans.json',self.scans),('security-result.json',self.native),('inventory-binding.json',self.binding)):
            (self.bundle / name).write_text(json.dumps(value))
        self.result['nativeScanSha256']=prepare.file_hash(self.bundle/'security-result.json')
        self.result['inventoryTransferSha256']=prepare.file_hash(self.bundle/'inventory-binding.json')
        (self.bundle/'ci-result.json').write_text(json.dumps(self.result))
        if self.original is not None:
            (self.bundle/'original-ci-result.json').write_text(json.dumps(self.original))
            (self.bundle/'original-boot.log').write_bytes(self.original_log)

    def invoke(self, write=True, memory_limit=512*1024**2):
        if write:self.write_bundle()
        state=self.root/'state.json';state.write_text(json.dumps(self.state))
        env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ['PATH'],PYTHONDONTWRITEBYTECODE='1',
            MAESTRO_NATIVE_PREPARE_POLICY=str(self.policy),NATIVE_FIXTURE_STATE=str(state),
            NATIVE_FIXTURE_CALLS=str(self.calls),NATIVE_FIXTURE_BUNDLE=str(self.bundle))
        extra=[] if self.boot_origin is None else ['--boot-origin-run',str(self.boot_origin[0]),
            '--boot-origin-attempt',str(self.boot_origin[1]),'--boot-origin-revision',self.boot_origin[2]]
        def limit():resource.setrlimit(resource.RLIMIT_AS,(memory_limit,memory_limit))
        return subprocess.run([sys.executable,str(SOURCE),'--directory',str(self.bundle),'--run','7','--attempt','1','--revision',SHA,*extra],
            env=env,capture_output=True,text=True,timeout=60,preexec_fn=limit)

    def blocked(self, write=True):
        result=self.invoke(write);self.assertEqual(result.returncode,2,result.stdout+result.stderr);self.assertEqual(result.stdout,'')

    def test_success_is_inactive_and_only_uses_get_and_signature_verification(self):
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout)
        self.assertFalse(value['authorization']);self.assertFalse(value['publicationReady'])
        self.assertFalse(value['riskAcceptanceEvaluated']);self.assertFalse(value['narBytesVerified']);self.assertFalse(value['isoBytesVerified'])
        self.assertEqual((value['rootCount'],value['boundDocumentCount']),(5,10))
        calls=[json.loads(v) for v in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls),7)
        self.assertTrue(all(c[:3]==['api','--method','GET'] or c[:2]==['attestation','verify'] for c in calls))
        workflows='\n'.join(p.read_text() for p in (ROOT/'.github/workflows').glob('*.yml'))
        self.assertNotIn('ci:native:prepare',workflows)
        self.assertNotIn('maestro-ci-native-prepare',workflows)

    def test_retained_boot_requires_one_exact_signed_executed_origin(self):
        self.retained();result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout);self.assertEqual(value['bootDisposition'],'verified-retained')
        self.assertEqual(value['bootOrigin'],dict(runId=8,runAttempt=2,revision='b'*40))
        self.assertFalse(value['isoBytesVerified']);self.assertFalse(value['publicationReady'])
        calls=[json.loads(v) for v in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls),9)
        self.assertTrue(any(c[:2]==['attestation','verify'] and c[2].endswith('/original-ci-result.json') for c in calls))

    def test_retained_missing_wrong_attempt_signature_and_recursive_origin_fail(self):
        self.retained();original=deepcopy(self.original)
        for change in ({'producer':prepare.origin_identity(8,3,'b'*40)},
                       {'boot':dict(original['boot'],disposition='verified-retained')},
                       {'boot':dict(original['boot'],isoSha256='a'*64)},
                       {'boot':dict(original['boot'],mediaInput='a'*64)},
                       {'boot':dict(original['boot'],verifierSha256='a'*64)},
                       {'boot':dict(original['boot'],origin=prepare.origin_identity(9,2,'b'*40))},
                       {'jobs':dict(original['jobs'],AUDIT_RESULT='skipped')}):
            with self.subTest(change=change):
                self.original={**deepcopy(original),**change};self.blocked()
        self.original=original;self.state['forgedOriginal']=True;self.blocked()
        self.state.pop('forgedOriginal');self.original_log=b'forged log';self.blocked()
        self.original_log=b'Reached target Multi-User System\n';self.write_bundle()
        (self.bundle/'original-ci-result.json').unlink();self.blocked(False)

    def test_retained_origin_api_and_current_scope_changes_fail(self):
        self.retained();run=deepcopy(self.state['originalRun'])
        for key,value in [('run_attempt',3),('head_sha','c'*40),('event','pull_request'),
                          ('path','.github/workflows/security.yml'),('conclusion','failure')]:
            with self.subTest(key=key):self.state['originalRun']={**run,key:value};self.blocked()
        self.state['originalRun']=run
        self.result['boot']['origin']['runId']=9;self.blocked()
        self.result['boot']['origin']['runId']=8;self.state['mainAfter']='e'*40;self.blocked()
        self.state.pop('mainAfter');self.native['scannerHealth']='failed';self.blocked()

    def test_retained_requires_explicit_new_iso_binding_not_null_acceptance(self):
        self.retained();binding=deepcopy(self.result['inventoryIsoBinding'])
        for value in (None,dict(binding,isoSha256='a'*64),dict(binding,inventorySha256='a'*64),
                      dict(binding,producer=prepare.origin_identity(8,2,'b'*40)),dict(binding,schemaVersion=2),dict(binding,schemaVersion=True)):
            with self.subTest(value=value):self.result['inventoryIsoBinding']=value;self.blocked()
        self.result['inventoryIsoBinding']=binding;self.binding['isoSha256']='a'*64;self.blocked()

    def test_measured_size_reports_parse_sequentially_with_strict_resource_limit(self):
        # Generated data only, larger than both measured production reports.
        self.native['diagnostics']=['x'*4096]*13600
        outcome=self.invoke();self.assertEqual(outcome.returncode,0,outcome.stderr)
        self.assertGreater((self.bundle/'scans.json').stat().st_size,55_706_156)
        self.assertGreater((self.bundle/'security-result.json').stat().st_size,52_521_292)
        self.assertFalse(json.loads(outcome.stdout)['authorization'])
        exhausted=self.invoke(False,memory_limit=96*1024**2)
        self.assertEqual(exhausted.returncode,2,exhausted.stdout+exhausted.stderr)
        self.assertEqual(exhausted.stdout,'')
        self.assertIn('MemoryError',exhausted.stderr)
        print(json.dumps({'generatedReportFixture':True,'maxChildRssKiB':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            'validationAddressSpaceLimitMiB':512,'livePreparation':False}))

    def test_aggregate_bound_and_duplicate_profile_are_still_rejected(self):
        self.write_bundle()
        with tempfile.TemporaryDirectory() as target, patch.object(prepare,'MAX_BUNDLE',1024):
            with self.assertRaises(ValueError):prepare.snapshot(self.bundle,Path(target))
        raw=(self.bundle/'scans.json').read_text().replace('"profiles": {','"profiles": {"maestro": {},',1)
        (self.bundle/'scans.json').write_text(raw);self.blocked(False)

    def test_validation_heap_limit_is_restored_even_after_failure(self):
        before=resource.getrlimit(resource.RLIMIT_AS)
        with self.assertRaises(ValueError):
            with prepare.bounded_validation():
                self.assertLessEqual(resource.getrlimit(resource.RLIMIT_AS)[0],512*1024**2)
                raise ValueError('fixture failure')
        self.assertEqual(resource.getrlimit(resource.RLIMIT_AS),before)

    def test_raw_native_and_scan_content_must_remain_equal(self):
        self.write_bundle()
        raw=(self.bundle/'scans.json').read_text().replace('"scannerHealth": "healthy"','"scannerHealth": "failed"')
        (self.bundle/'scans.json').write_text(raw);self.blocked(False)
        self.write_bundle();raw=(self.bundle/'security-result.json').read_text().replace('"status": "complete"','"status": NaN')
        (self.bundle/'security-result.json').write_text(raw);self.blocked(False)

    def test_high_finding_is_observed_without_accepting_risk(self):
        root=self.subjects[0]['storePath']
        self.native['observations']=[dict(component='pkg:npm/lodash@4.17.15',advisory='CVE-2020-8203',
            aliases=[],severity='High',knownExploited=False,cvss=7.4,locations=[root+'/lib/module.js'],
            locationCoverage='complete',fixVersions=['4.17.21'],exposureBindings=[dict(location=root+'/lib/module.js',
                outputName='out',relativePath='lib/module.js')])]
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(json.loads(result.stdout)['authorization'])
        self.assertFalse(json.loads(result.stdout)['riskAcceptanceEvaluated'])

    def test_oversized_external_response_is_bounded(self):
        self.state['oversizedResponse']=True;self.blocked()

    def test_wrong_run_repository_workflow_event_ref_sha_attempt_or_status(self):
        original=deepcopy(self.state['run'])
        for field,value in [('id',8),('run_attempt',2),('head_sha','f'*40),('head_branch','feature'),
                            ('repository',{'full_name':'evil/fork'}),('head_repository',{'full_name':'evil/fork'}),
                            ('path','.github/workflows/security.yml'),('event','pull_request'),('status','in_progress'),('conclusion','failure')]:
            with self.subTest(field=field):
                self.state['run']={**original,field:value};self.blocked()

    def test_main_or_policy_changes_reject(self):
        self.state['mainAfter']='e'*40;self.blocked()
        self.state.pop('mainAfter');self.state['policy']={**self.cfg,'maxEvidenceAgeHours':48};self.blocked()

    def test_forged_subject_or_failed_attestation_reject(self):
        self.state['forgedSubject']=True;self.blocked()
        self.state.pop('forgedSubject');self.state['proofFailure']=True;self.blocked()

    def test_missing_required_checks_attempt_or_boot_cannot_be_called_success(self):
        self.result['jobs']['SCAN_RESULT']='skipped';self.blocked()
        self.result['jobs']['SCAN_RESULT']='success';self.result['boot']['disposition']='verified-retained';self.blocked()
        self.result['boot']['disposition']='executed';self.scans['producer']['runAttempt']=2;self.blocked()

    def test_package_only_context_cannot_replace_installer_policy(self):
        self.native['securityContext']['schema']=1
        del self.native['securityContext']['installer'];self.blocked()

    def test_stale_future_database_and_health_fail(self):
        original=deepcopy(self.native)
        changes=[{'scannerHealth':'failed'},{'database':{'valid':False,'built':original['database']['built']}},
            {'database':{'valid':True,'built':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=3)).isoformat()}},
            {'scannedAt':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat()}]
        for change in changes:
            with self.subTest(change=change):self.native.clear();self.native.update(deepcopy(original));self.native.update(change);self.blocked()

    def test_subject_nar_coverage_and_cache_scope_substitutions_fail(self):
        self.product['roots']['maestro-menu']['narHash']='sha256-'+'B'*43+'=';self.blocked()
        self.product['roots']['maestro-menu']['narHash']=NAR
        self.native['coverage']['manifest']['roots']['unscanned']='/nix/store/'+'z'*32+'-missing';self.blocked()
        del self.native['coverage']['manifest']['roots']['unscanned']
        self.product['cachePublication']['roots'].append('appliance');self.blocked()

    def test_document_swap_missing_extra_binding_and_symlink_fail(self):
        self.write_bundle();p=self.bundle/prepare.DOCUMENTS[0];p.write_text('forged');self.blocked(False)
        p.unlink();self.blocked(False)
        p.symlink_to(self.policy);self.blocked(False)
        p.unlink();p.write_text('native fixture '+prepare.DOCUMENTS[0]);self.binding['evidenceFiles']['extra.json']='f'*64;self.blocked()

    def test_resource_and_nonregular_input_bounds(self):
        self.write_bundle();p=self.bundle/'scans.json'
        with p.open('wb') as out:out.truncate(prepare.MAX_REPORT+1)
        self.blocked(False)
        p.unlink();os.mkfifo(p);self.blocked(False)

    def test_local_row_mutation_and_duplicate_json_fields_reject(self):
        self.write_bundle();(self.bundle/'security-result.json').write_text('{}');self.blocked(False)
        self.write_bundle();(self.bundle/'product.json').write_text('{"schema":1,"schema":1}');self.blocked(False)


if __name__=='__main__':unittest.main()
