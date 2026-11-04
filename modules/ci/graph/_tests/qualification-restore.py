#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Only authenticated exact native bytes may restore a qualification store."""
from copy import deepcopy
import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).parents[4] / ('modules/features/installer/_source' if name == 'qualification-restore' else 'modules/ci/security/_source') / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


restore = load('qualification-restore')
health = load('security-native-check')
ROOT = '/nix/store/' + 'a' * 32 + '-fixture'
REVISION = 'b' * 40
NAR = 'sha256-' + 'A' * 43 + '='
roots = [{'storePath': ROOT, 'narHash': NAR}]


def reject(call, message=None):
    try:
        call()
    except ValueError as error:
        if message:
            assert message in str(error), str(error)
        return
    raise AssertionError('unsafe qualification restore accepted')


with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    sbom = {'properties': [{'name': 'maestro:inventoryRoots', 'value': json.dumps(roots)}]}
    path = directory / 'maestro-system.cdx.json'
    path.write_text(json.dumps(sbom))
    native = {'evidence': {'inventory': {'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}}}
    scans = {'profiles': {'maestro': native}, 'transport': {'authenticated': 'manifest'}}
    product = {'revision': REVISION, 'products': {'maestro': roots[0]}, 'roots': {'same': {**roots[0], 'profile': 'maestro'}}}
    events = []
    transfer = SimpleNamespace(restore=Mock(side_effect=lambda *args: events.append('import')), verify_roots=Mock())
    with patch.object(restore.common, 'scans', side_effect=lambda *args, **kwargs: (events.append(('authenticated-scan', kwargs)) or scans)), \
            patch.object(restore.common, 'product', side_effect=lambda *args: (events.append('authenticated-product') or product)):
        # Policy disabled is deliberate: candidate preparation must precede risk
        # acceptance. Publication uses another leaf with the human gate intact.
        result = restore.restore({'enabled': False}, directory, directory, {ROOT}, transfer, REVISION)
        assert result['status'] == 'restored-for-native-qualification'
        assert events == [('authenticated-scan', {'allow_expired': True}), 'authenticated-product', 'import']
        transfer.restore.assert_called_once_with(directory, scans['transport'], roots)
        transfer.restore.reset_mock()
        # Old seven-root products retain their original authenticated bytes for
        # historical audit. Import never upgrades them to installer coverage.
        historical = restore.restore({}, directory, directory, {ROOT, ROOT + '-installer'}, transfer,
                                     legacy_paths={ROOT})
        assert historical['coverage'] == 'historical-only'
        assert 'coverage' not in scans['profiles']['maestro']
        transfer.restore.reset_mock()
        reject(lambda: restore.restore({}, directory, directory, {ROOT + '-other'}, transfer), 'current evaluated')
        reject(lambda: restore.restore({}, directory, directory, {ROOT}, transfer, 'c' * 40), 'exact candidate')
        path.write_text(json.dumps({'properties': []}))
        reject(lambda: restore.restore({}, directory, directory, {ROOT}, transfer), 'authenticated native producer')
        transfer.restore.assert_not_called()
    with patch.object(restore.common, 'scans', side_effect=ValueError('bad attestation')):
        reject(lambda: restore.restore({}, directory, directory, {ROOT}, transfer), 'bad attestation')
        transfer.restore.assert_not_called()

now = dt.datetime.now(dt.timezone.utc)
context = {'schema': 1, 'tcpPorts': [], 'udpPorts': [], 'managementCIDRs': ['0.0.0.0/0'],
           'ssh': {}, 'execution': {'xoUser': 'xo', 'User': 'xo', 'Group': 'xo'},
           'capabilities': [], 'ambientCapabilities': [],
           'helpers': {'enableNFS': False, 'enableCIFS': False, 'enableVHD': False, 'fileRestore': False},
           'sudo': [], 'mountsDir': '/run/xo'}
native = {'status': 'complete', 'scannerHealth': 'healthy', 'observations': [], 'securityContext': context,
          'scannedAt': (now - dt.timedelta(minutes=1)).isoformat(),
          'database': {'valid': True, 'built': (now - dt.timedelta(hours=1)).isoformat()}}
assert health.check(native, {})['status'] == 'healthy-native-qualification'
stale = deepcopy(native)
stale['scannedAt'] = (now - dt.timedelta(days=2)).isoformat()
reject(lambda: health.check(stale, {}), 'Stale native qualification')
missing = deepcopy(native)
del missing['securityContext']
reject(lambda: health.check(missing, {}), 'runtime policy coverage')
print('Identity-only candidate restore, authentication order and fresh native health fixtures passed.')


class CacheFirst(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        sbom = self.directory / 'maestro-system.cdx.json'
        sbom.write_text(json.dumps({'properties': [{'name': 'maestro:inventoryRoots', 'value': json.dumps(roots)}]}))
        self.scans = {'profiles': {'maestro': {'evidence': {'inventory': {
            'sha256': hashlib.sha256(sbom.read_bytes()).hexdigest()}}}}, 'transport': {'authenticated': 'manifest'}}
        self.product = {'revision': REVISION, 'products': {'maestro': roots[0]}}
        self.transfer = SimpleNamespace(restore=Mock(), verify_roots=Mock())
        self.fetch = Mock()
        self.substitute = Mock(return_value=True)
        self.patches = [patch.object(restore.common, 'scans', return_value=self.scans),
                        patch.object(restore.common, 'product', return_value=self.product)]
        for p in self.patches:
            p.start(); self.addCleanup(p.stop)

    def invoke(self):
        return restore.restore({}, self.directory, self.directory, {ROOT}, self.transfer,
                               REVISION, substitute=self.substitute, ensure_transport=self.fetch)

    def test_cache_hit_verifies_nars_and_avoids_bulk_transfer(self):
        self.assertEqual(self.invoke()['transportSource'], 'configured-substituters')
        self.transfer.verify_roots.assert_called_once_with(roots)
        self.transfer.restore.assert_not_called(); self.fetch.assert_not_called()

    def test_miss_fetches_and_restores_exactly_once(self):
        self.substitute.return_value = False
        self.assertEqual(self.invoke()['transportSource'], 'producer-artifact')
        self.fetch.assert_called_once_with(self.directory, self.scans)
        self.transfer.restore.assert_called_once_with(self.directory, self.scans['transport'], roots)

    def test_bad_nar_identity_is_failure_without_fallback(self):
        self.transfer.verify_roots.side_effect = ValueError('wrong NAR')
        with self.assertRaisesRegex(ValueError, 'wrong NAR'): self.invoke()
        self.fetch.assert_not_called(); self.transfer.restore.assert_not_called()

    def test_authentication_failure_never_queries_cache(self):
        with patch.object(restore.common, 'scans', side_effect=ValueError('bad signature')):
            with self.assertRaises(ValueError): self.invoke()
        self.substitute.assert_not_called(); self.fetch.assert_not_called()

    def test_changed_roots_reject_before_cache(self):
        self.product['products']['maestro'] = dict(roots[0], storePath=ROOT+'-other')
        with self.assertRaises(ValueError): self.invoke()
        self.substitute.assert_not_called(); self.fetch.assert_not_called()

    def test_substitution_cannot_grant_human_risk_acceptance(self):
        result = self.invoke()
        self.assertNotIn('authorization', result)
        self.assertNotIn('riskAcceptance', result)

    def test_lazy_transfer_rechecks_exact_producer_and_inventory(self):
        scans = dict(self.scans, revision=REVISION, producer=dict(runId=123, runAttempt=1, workflow='.github/workflows/ci.yml'))
        run = dict(id=123, run_attempt=1, head_sha=REVISION, path='.github/workflows/ci.yml')
        downloader = SimpleNamespace(trusted=Mock(return_value=True), api=Mock(side_effect=[run, {'total_count':0,'artifacts':[]}]), distribution_transport=Mock())
        restore.fetch_transport(self.directory, scans, downloader)
        downloader.distribution_transport.assert_called_once()
        for changed in (dict(run, run_attempt=2), dict(run, head_sha='f'*40), dict(run, path='.github/workflows/security.yml')):
            downloader.api.side_effect = [changed]; downloader.distribution_transport.reset_mock()
            with self.assertRaises(ValueError): restore.fetch_transport(self.directory, scans, downloader)
            downloader.distribution_transport.assert_not_called()
        downloader.api.side_effect = [run, {'total_count':1,'artifacts':[]}]
        with self.assertRaises(ValueError): restore.fetch_transport(self.directory, scans, downloader)

    def test_packaged_lazy_reader_works_without_source_tree_siblings(self):
        scans = dict(self.scans, revision=REVISION, producer=dict(runId=123, runAttempt=1, workflow='.github/workflows/ci.yml'))
        reader = self.directory/'reader.py'
        reader.write_text('from pathlib import Path\n'
            'def trusted(run):return True\n'
            'def api(endpoint):\n'
            ' if endpoint=="actions/runs/123":return '+repr(dict(id=123,run_attempt=1,head_sha=REVISION,path='.github/workflows/ci.yml'))+'\n'
            ' return {"total_count":0,"artifacts":[]}\n'
            'def distribution_transport(evidence,scans,run,inventory):\n'
            ' (evidence/"lazy-reader-called").write_text(str(run["id"]))\n')
        with patch.dict(os.environ,{'MAESTRO_DECISION_DOWNLOAD_SOURCE':str(reader)}), \
                patch.object(restore.common,'__file__',str(self.directory/'isolated-decisions/common.py')):
            restore.fetch_transport(self.directory,scans)
        self.assertEqual((self.directory/'lazy-reader-called').read_text(),'123')
        package = Path(__file__).parents[4]/'modules/features/installer/_lib/commands.nix'
        self.assertIn('MAESTRO_DECISION_DOWNLOAD_SOURCE=${../../../ci/authority/_source/decision-download.py}',package.read_text())


class NativeSubprocess(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.log = self.root/'calls.jsonl'
        executable = self.root/'nix-store'
        executable.write_text('#!'+sys.executable+'\nimport json,os,sys,time\n'
            'with open(os.environ["CACHE_TEST_LOG"],"a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\n'
            'if os.environ.get("CACHE_TEST_SLEEP"):time.sleep(60)\n'
            'sys.exit(int(os.environ.get("CACHE_TEST_EXIT","0")))\n')
        executable.chmod(0o700)
        self.environment = patch.dict(os.environ,dict(PATH=str(self.root)+os.pathsep+os.environ['PATH'],CACHE_TEST_LOG=str(self.log)))
        self.environment.start(); self.addCleanup(self.environment.stop)

    def test_real_contract_disables_all_builds_and_preserves_cache_trust(self):
        with patch.object(Path, 'exists', return_value=True): self.assertTrue(restore.cache_roots({ROOT}))
        calls = [json.loads(s) for s in self.log.read_text().splitlines()]
        self.assertEqual(len(calls),2); self.assertIn('--dry-run',calls[0]); self.assertNotIn('--dry-run',calls[1])
        for args in calls:
            self.assertEqual(args[-1],ROOT)
            for name,value in [('max-jobs','0'),('builders',''),('fallback','false'),('require-sigs','true')]:
                pos=args.index(name); self.assertEqual(args[pos-1],'--option'); self.assertEqual(args[pos+1],value)
            self.assertNotIn('substituters',args); self.assertNotIn('trusted-public-keys',args)

    def test_probe_failure_never_fetches(self):
        with patch.dict(os.environ,{'CACHE_TEST_EXIT':'1'}): self.assertFalse(restore.cache_roots({ROOT}))
        self.assertEqual(len(self.log.read_text().splitlines()),1)

    def test_real_subprocess_uses_only_packaged_flake_cache_extensions(self):
        cfg = self.root/'caches.json'
        cfg.write_text(json.dumps({'substituters':['https://fixture.invalid/cache'], 'keys':['fixture-1:key']}))
        with patch.dict(os.environ,{'MAESTRO_QUALIFICATION_CACHE_CONFIG':str(cfg)}), patch.object(Path,'exists',return_value=True):
            self.assertTrue(restore.cache_roots({ROOT}))
        for args in map(json.loads,self.log.read_text().splitlines()):
            self.assertEqual(args[args.index('extra-substituters')+1],'https://fixture.invalid/cache')
            self.assertEqual(args[args.index('extra-trusted-public-keys')+1],'fixture-1:key')
            self.assertNotIn('substituters',args); self.assertNotIn('trusted-public-keys',args)

    def test_bad_packaged_cache_configuration_fails_without_fallback(self):
        cfg = self.root/'caches.json'; cfg.write_text('{"substituters":["not a URL"],"keys":[]}')
        with patch.dict(os.environ,{'MAESTRO_QUALIFICATION_CACHE_CONFIG':str(cfg)}):
            with self.assertRaises(ValueError): restore.cache_roots({ROOT})
        self.assertFalse(self.log.exists())

    def test_real_timeout_cleanup_is_a_cache_miss(self):
        with patch.dict(os.environ,{'CACHE_TEST_SLEEP':'true'}), restore.common.operations.budget(0.2):
            self.assertFalse(restore.cache_roots({ROOT}))

    def test_derivations_and_non_store_arguments_never_execute(self):
        for value in (ROOT+'.drv','--option','/tmp/output'):
            with self.assertRaises(ValueError): restore.cache_roots({value})
        self.assertFalse(self.log.exists())


if __name__ == '__main__':
    unittest.main()
