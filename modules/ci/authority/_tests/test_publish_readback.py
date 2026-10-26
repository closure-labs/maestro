# SPDX-License-Identifier: Apache-2.0
"""Exercise fresh approved-cache readback without writing public state."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[4]
CACHE = 'https://maestro.cachix.org'
UPSTREAM = 'https://cache.nixos.org'
FAKE = '''
import fcntl, json, os, pathlib, sys, time
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
fixture = json.loads(pathlib.Path(os.environ.get('PUBLISH_FIXTURE', pathlib.Path(sys.argv[0]).parent.parent / 'fixture.json')).read_text())
def record_call(call):
    # Metadata probes run concurrently. A reader can otherwise observe an
    # incomplete appended JSON line, causing a spurious fake transport failure.
    with open(os.environ.get('PUBLISH_CALLS', pathlib.Path(sys.argv[0]).parent.parent / 'calls.jsonl'), 'a+') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(json.dumps(call) + '\\n')
        stream.flush()
        stream.seek(0)
        return [json.loads(line) for line in stream.read().splitlines()]
previous = record_call([name, *([os.environ.get('PUBLICATION_PURPOSE','')] if name.startswith('maestro-ci-') else []), *args])
if name == 'curl':
    if fixture.get('require_public_environment') and any(key in os.environ for key in ('GH_TOKEN','GITHUB_TOKEN','REGISTRY_TOKEN','XO_AUTHORITY_TOKEN','CACHIX_MAESTRO_AUTH_TOKEN','CACHIX_AUTH_TOKEN')):sys.exit(2)
    uploaded = any(call[0] == 'cachix' for call in previous)
    if uploaded and fixture.get('hang'):
        time.sleep(10)
    if uploaded and fixture.get('exit'):
        sys.stderr.write('fixture-secret untrusted remote details')
        sys.exit(1)
    key = pathlib.Path(args[-1]).name.removesuffix('.narinfo')
    path = next(path for path in fixture['local'] if pathlib.Path(path).name.startswith(key))
    if args[-1].startswith('https://maestro.cachix.org/'):
        record = fixture['remote'].get(path) if uploaded and isinstance(fixture['remote'],dict) else None
        if fixture.get('already_verified') or path in fixture.get('existing',[]):record={'narHash':fixture['local'][path]}
        if not uploaded and path in fixture.get('existing_overrides',{}):record=fixture['existing_overrides'][path]
        if path in fixture.get('upstream',[]):record=None
        raw = fixture['remote'] if uploaded and isinstance(fixture['remote'],str) else None
    else:
        record={'narHash':fixture['local'][path]} if path in fixture.get('upstream',[]) else None
        raw=None
    data=b'';status='404'
    if raw is not None:data=raw.encode();status='200'
    elif record is not None:
        data=('StorePath: '+record.get('path',path)+'\\nNarHash: '+record.get('narHash','')+'\\nNarSize: 1\\nURL: nar/fixture.nar.zst\\nReferences: '+(' '.join(pathlib.Path(p).name for p in fixture.get('references',{}).get(path,[])))+'\\n').encode();status='200'
    pathlib.Path(args[args.index('--output')+1]).write_bytes(data)
    print(status,end='')
elif name == 'maestro-ci-decision-publication':
    if fixture.get('mutate_input_at') == sum(call[0]==name for call in previous):
        target = pathlib.Path(os.environ['DECISION_SCANS'])
        target.chmod(0o600)
        target.write_text('{}')
    if sum(call[0]==name for call in previous)==fixture.get('deny_authority_at'):sys.exit(1)
    if fixture.get('deny_release') and os.environ.get('PUBLICATION_PURPOSE')=='release':sys.exit(1)
elif name == 'maestro-ci-distribution-restore':
    pathlib.Path(os.environ['DISTRIBUTION_CLOSURE_METADATA']).write_text(json.dumps({path:{'narHash':digest} for path,digest in fixture['local'].items()}))
elif name == 'nix':
    print(json.dumps({path:{'narHash':digest} for path,digest in fixture['local'].items()}))
elif name == 'cachix':
    record_call(['uploaded',*sys.stdin.read().splitlines()])
'''


class PublishReadback(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.work=Path(self.temporary.name);self.native=self.work/'bin';self.native.mkdir()
        for name in ('curl','nix','cachix','maestro-ci-decision-publication',
                     'maestro-ci-distribution-restore','maestro-ci-decision-handoff'):
            executable=self.native/name;executable.write_text('#!'+sys.executable+'\n'+FAKE);executable.chmod(0o755)
        self.paths=['/nix/store/'+str(i)*32+'-fixture-'+str(i) for i in range(8)]
        self.local={path:'sha256-'+'A'*43+'=' for path in self.paths}
        entries=[{'storePath':path,'narHash':value} for path,value in self.local.items()]
        self.product={'products':dict(zip(('latest','stable','rolling'),entries[:3])),
                      'roots':{str(i):entry for i,entry in enumerate(entries[3:])},
                      'repository':'closure-labs/maestro','revision':'a'*40,'assets':{}}
        (self.work/'product.json').write_text(json.dumps(self.product));(self.work/'scans.json').write_text('{}')
        self.calls=self.work/'calls.jsonl';self.fixture=self.work/'fixture.json';self.receipt=self.work/'receipt.json'
        self.env=dict(os.environ,PATH=str(self.native)+os.pathsep+os.environ['PATH'],
                      MAESTRO_CI_PATH_PREFIX=str(self.native),
                      PUBLISH_FIXTURE=str(self.fixture),PUBLISH_CALLS=str(self.calls),
                      DECISION_PRODUCT=str(self.work/'product.json'),DECISION_SCANS=str(self.work/'scans.json'),
                      GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REF='refs/heads/main',
                      CACHIX_MAESTRO_AUTH_TOKEN='fixture-secret',
                      CACHIX_MAESTRO_PUBKEY='maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0=',
                      PUBLICATION_CACHE_RECEIPT=str(self.receipt))

    def run_leaf(self,remote=None,**fixture):
        if remote is None:remote={path:{'narHash':digest} for path,digest in self.local.items()}
        self.fixture.write_text(json.dumps(dict(fixture,remote=remote,local=self.local)))
        self.env.pop('PYTHONPATH',None)
        command=([os.environ['MAESTRO_TEST_PUBLISH_COMMAND']] if os.environ.get('MAESTRO_TEST_PUBLISH_COMMAND')
                 else ['bash',str(ROOT/'modules/release/publication/_source/publish.sh')])
        result=subprocess.run(command,env=self.env,
                              text=True,capture_output=True,timeout=20)
        calls=[json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []
        return result,calls

    def assert_rejected(self,remote=None,**fixture):
        result,calls=self.run_leaf(remote,**fixture)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(sum(call[0]=='cachix' for call in calls),1,
                         f'publisher exit={result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}')
        self.assertFalse(self.receipt.exists())
        self.assertNotIn('fixture-secret',result.stdout+result.stderr)
        self.assertNotIn('untrusted remote details',result.stdout+result.stderr)
        return result,calls

    def test_all_exact_paths_have_fresh_bounded_readback_after_push(self):
        result,calls=self.run_leaf();self.assertEqual(result.returncode,0,result.stderr)
        push=next(i for i,c in enumerate(calls) if c[0]=='cachix')
        reads=[c for c in calls[push+1:] if c[0]=='curl']
        self.assertEqual({c[-1] for c in reads},{CACHE+'/'+Path(p).name[:32]+'.narinfo' for p in self.paths})
        self.assertTrue(all(c[c.index('--max-time')+1]=='30' for c in reads))
        receipt=json.loads(self.receipt.read_text());self.assertEqual(receipt['schema'],1)
        self.assertEqual(receipt['expected'],self.local);self.assertEqual(receipt['observed'],self.local)

    def test_stock_upstream_root_is_verified_without_reupload(self):
        result,calls=self.run_leaf(upstream=[self.paths[0]]);self.assertEqual(result.returncode,0,result.stderr)
        uploaded=next(c[1:] for c in calls if c[0]=='uploaded');self.assertNotIn(self.paths[0],uploaded)
        self.assertTrue(any(c[0]=='curl' and c[-1].startswith(UPSTREAM+'/') for c in calls))
        self.assertEqual(json.loads(self.receipt.read_text())['observed'],self.local)

    def test_verified_noop_has_no_restore_handoff_or_upload(self):
        result,calls=self.run_leaf(already_verified=True);self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(any(c[0] in ('cachix','maestro-ci-distribution-restore','maestro-ci-decision-handoff') for c in calls))
        self.assertTrue(self.receipt.exists())

    def test_metadata_inspection_uses_same_upstreams_and_avoids_restore(self):
        self.fixture.write_text(json.dumps({'local':self.local,'remote':{},'upstream':self.paths}))
        env=dict(self.env,PUBLICATION_DESTINATION='cache',
                 PUBLICATION_DESTINATIONS_SOURCE=str(ROOT/'modules/ci/authority/_source/decisions/destinations.py'),
                 PUBLICATION_REQUIRE_VERIFIED='true',PUBLICATION_RECEIPT=str(self.receipt),
                 GITHUB_OUTPUT=str(self.work/'output'))
        env.pop('PYTHONPATH',None)
        command=([os.environ['MAESTRO_TEST_INSPECT_COMMAND']] if os.environ.get('MAESTRO_TEST_INSPECT_COMMAND')
                 else ['bash',str(ROOT/'modules/release/publication/_source/publication-inspect.sh')])
        result=subprocess.run(command,env=env,
                              capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'],'verified')
        self.assertEqual((self.work/'output').read_text(),'status=verified\n')
        calls=[json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(all(call[0]=='curl' for call in calls))
        self.assertTrue(self.receipt.exists())

    def test_present_roots_with_missing_child_restore_and_upload_only_bound_dependency(self):
        child='/nix/store/'+'a'*32+'-retained-child'
        self.local[child]='sha256-'+'A'*43+'='
        result,calls=self.run_leaf(existing=self.paths,references={self.paths[0]:[child]})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(next(c[1:] for c in calls if c[0]=='uploaded'),[child])
        self.assertTrue(any(c[0]=='maestro-ci-distribution-restore' for c in calls))
        receipt=json.loads(self.receipt.read_text())
        self.assertEqual(set(receipt['expected']),set(self.paths))
        self.assertEqual(receipt['expected'],receipt['observed'])

    def test_retained_dependency_conflict_blocks_before_any_upload(self):
        child='/nix/store/'+'a'*32+'-retained-child'
        self.local[child]='sha256-'+'A'*43+'='
        result,calls=self.run_leaf(existing=[*self.paths[:-1],child],
            existing_overrides={child:{'narHash':'sha256-'+'B'*43+'='}},
            references={self.paths[0]:[child]})
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(c[0]=='cachix' for c in calls))
        self.assertFalse(self.receipt.exists())

    def test_authority_revoked_after_handoff_blocks_cache_write(self):
        result,calls=self.run_leaf(deny_authority_at=3)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(any(c[0]=='maestro-ci-decision-handoff' for c in calls))
        self.assertFalse(any(c[0]=='cachix' for c in calls))
        self.assertFalse(self.receipt.exists())


    def test_official_recovery_propagates_release_purpose_to_every_gate_and_restore(self):
        self.env['PUBLICATION_PURPOSE']='release'
        result,calls=self.run_leaf()
        self.assertEqual(result.returncode,0,result.stderr)
        native=[c for c in calls if c[0].startswith('maestro-ci-')]
        self.assertTrue(any(c[0]=='maestro-ci-distribution-restore' for c in native))
        self.assertTrue(all(c[1]=='release' for c in native))
        self.assertTrue(self.receipt.exists())

    def test_release_approval_denial_and_invalid_purpose_cannot_upload(self):
        for purpose in ('release','invalid'):
            self.env['PUBLICATION_PURPOSE']=purpose
            result,calls=self.run_leaf(deny_release=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(any(c[0]=='cachix' for c in calls))
            self.assertFalse(self.receipt.exists())
            self.calls.unlink(missing_ok=True)

    def test_same_path_wrong_hash_is_rejected(self):
        for path in self.paths:
            with self.subTest(path=path):
                remote={p:{'narHash':v} for p,v in self.local.items()};remote[path]['narHash']='sha256-'+'B'*43+'='
                self.assert_rejected(remote);self.calls.unlink()

    def test_missing_and_wrong_store_path_are_rejected(self):
        for mode in ('missing','path'):
            remote={p:{'narHash':v} for p,v in self.local.items()}
            if mode=='missing':del remote[self.paths[0]]
            else:remote[self.paths[0]]['path']='/nix/store/'+'z'*32+'-unexpected'
            self.assert_rejected(remote);self.calls.unlink()

    def test_malformed_metadata_is_rejected(self):
        for body in ('not-narinfo','{}','StorePath: wrong\nNarHash: invalid\nNarSize: 1\n'):
            self.assert_rejected(body);self.calls.unlink()

    def test_remote_failure_is_closed_without_raw_stderr(self):
        self.assert_rejected(exit=1)

    def test_stalled_remote_read_honors_inherited_budget(self):
        self.env['CI_OPERATION_DEADLINE']=str(time.monotonic()+3)
        start=time.monotonic();self.assert_rejected(hang=True)
        self.assertLess(time.monotonic()-start,5)


if __name__=='__main__':unittest.main()
