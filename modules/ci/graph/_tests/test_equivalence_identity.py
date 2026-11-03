#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mutation-driver guards; real Nix inventory identities are checked in hosted CI."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE=Path(__file__).parents[1]/'_source/equivalence.py'
APPLIANCE='nixosConfigurations-maestro-config-system-build-toplevel'
ISO='packages-x86_64-linux-installer-iso'
CLI='packages-x86_64-linux-maestroctl'
PACKER='packages-x86_64-linux-deploy-template'
PATHS={
    'documentation':'README.md',
    'cli':'modules/features/operator/cli/_source/maestroctl.sh',
    'xo-storage':'modules/features/xo/_source/storage-helper.sh',
    'installer':'modules/features/installer/_source/install-maestro.sh',
    'packer':'modules/features/xcp-ng/template/_source/build.sh',
    'scan-policy':'modules/ci/security/_source/security-policy.json',
    'scheduler':'modules/ci/graph/_source/graph.py',
    'binding-verifier':'modules/ci/graph/_source/bindings.py',
    'ci-routing':'.github/workflows/ci.yml',
    'inventory-generator':'modules/ci/inventory/_source/security-inventory.py',
}

class EquivalenceIdentity(unittest.TestCase):
    def execute(self,fault=None):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'checkout';root.mkdir();out=Path(temporary)/'observations';out.mkdir()
            before={}
            for name,path in PATHS.items():
                file=root/path;file.parent.mkdir(parents=True,exist_ok=True)
                before[name]=b'{}\n' if file.suffix=='.json' else b'# original fixture\n'
                file.write_bytes(before[name])
            original=dict(targets={key:dict(derivation=key+'-original') for key in (APPLIANCE,ISO,CLI,PACKER)},
                policy=dict(scan='original',boot='original',bootVerifier='original',qualificationInputs='original'))
            (out/'original.graph.json').write_text(json.dumps(original))
            state=dict(paths=PATHS,hashes={name:hashlib.sha256(raw).hexdigest() for name,raw in before.items()},
                appliance=APPLIANCE,iso=ISO,cli=CLI,packer=PACKER,root=str(root),out=str(out),fault=fault)
            state_path=Path(temporary)/'state.json';state_path.write_text(json.dumps(state))
            binary=Path(temporary)/'bin';binary.mkdir();nix=binary/'nix'
            nix.write_text('#!'+sys.executable+'\n'+'''import hashlib,json,os,sys
from pathlib import Path
state=json.loads(Path(os.environ['IDENTITY_FIXTURE']).read_text());root=Path(state['root'])
assert sys.argv[1:]==['eval','--accept-flake-config','--no-write-lock-file','--json','path:'+str(root)+'#lib.ciGraph.x86_64-linux']
active=[name for name,path in state['paths'].items() if hashlib.sha256((root/path).read_bytes()).hexdigest()!=state['hashes'][name]]
assert len(active)==1,active
name=active[0];graph=json.loads((Path(state['out'])/'original.graph.json').read_text())
changed={'cli':['appliance','iso','cli'],'xo-storage':['appliance','iso'],'installer':['iso'],'packer':['packer']}.get(name,[])
for target in changed:graph['targets'][state[target]]['derivation']+='-changed'
if name=='scan-policy':graph['policy']['scan']='changed'
if name=='binding-verifier':
 graph['policy']['boot']='changed';graph['policy']['bootVerifier']='changed'
if name=='inventory-generator' and state['fault']!='ignore-generator':graph['policy']['qualificationInputs']='changed'
if name=='ci-routing' and state['fault']=='routing-invalidates':graph['policy']['qualificationInputs']='changed'
if name=='ci-routing' and state['fault']=='evaluation-failure':raise SystemExit(17)
print(json.dumps(graph))
''');nix.chmod(0o700)
            result=subprocess.run([sys.executable,str(SOURCE),str(root),str(out),'a'*40,'b'*40],
                env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],IDENTITY_FIXTURE=str(state_path)),
                capture_output=True,text=True,timeout=20)
            # Both failed evaluations and failed invariants must restore sources.
            self.assertTrue(all((root/path).read_bytes()==before[name] for name,path in PATHS.items()))
            results=json.loads((out/'results.json').read_text())['results'] if (out/'results.json').exists() else []
            return result,results
    def test_current_driver_enforces_routing_stability_and_generator_invalidation(self):
        result,rows=self.execute();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual({row['case'] for row in rows},set(PATHS))
        self.assertTrue(all(row['status']=='passed' for row in rows))
    def test_changed_routing_fingerprint_or_ignored_generator_fails_closed(self):
        for fault in ('routing-invalidates','ignore-generator'):
            with self.subTest(fault=fault):
                result,rows=self.execute(fault);self.assertNotEqual(result.returncode,0)
                self.assertIn('unexpected inventory identity propagation',result.stderr)
                self.assertNotIn('inventory-generator' if fault=='ignore-generator' else 'ci-routing',{row['case'] for row in rows})
    def test_failed_nix_evaluation_is_not_recorded_as_success(self):
        result,rows=self.execute('evaluation-failure');self.assertNotEqual(result.returncode,0)
        self.assertIn('exit status 17',result.stderr)
        self.assertNotIn('ci-routing',{row['case'] for row in rows})

if __name__=='__main__':unittest.main()
