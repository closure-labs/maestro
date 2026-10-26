# SPDX-License-Identifier: Apache-2.0
import base64
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
CORE=Path(__file__).resolve().parents[2]
CORE=CORE/'ci/decisions' if (CORE/'ci').exists() else CORE/'modules/ci/authority/_source/decisions'
sys.path.insert(0,str(CORE))
import destinations as d
P='/nix/store/'+'0'*32+'-fixture'
H='sha256-'+base64.b64encode(bytes(32)).decode()
PRODUCT={'products':{'fixture':{'storePath':P,'narHash':H}},'revision':'a'*40}
BODY=f'StorePath: {P}\nNarHash: sha256:{"0"*52}\nNarSize: 1\nURL: nar/fixture.nar.zst\nReferences: \n'.encode()

class Destinations(unittest.TestCase):
    def test_cache_missing_partial_verified_conflict_unavailable(self):
        for code,body,state in [(404,b'','missing'),(200,BODY,'verified'),(503,b'','unavailable'),
                                (200,BODY.replace(b'NarSize: 1',b'NarSize: 0'),'conflict')]:
            with self.subTest(state=state):
                value=d.cache(PRODUCT,'https://maestro.cachix.org',lambda _: (code,body))
                self.assertEqual(value['status'],state)
                if state!='verified':
                    with self.assertRaises(ValueError):d.receipt(value,PRODUCT)
        value=d.cache(PRODUCT,'https://maestro.cachix.org',lambda _: (200,BODY))
        self.assertEqual(d.receipt(value,PRODUCT)['expected'],{P:H})

    def test_nix_base32_preserves_byte_order_and_high_bits(self):
        raw=bytes(range(32));number=int.from_bytes(raw,'little')
        encoded=''.join(d.ALPHABET[(number>>(5*i))&31] for i in reversed(range(52)))
        self.assertEqual(d.nar_hash('sha256:'+encoded),'sha256-'+base64.b64encode(raw).decode())
        with self.assertRaises(ValueError):d.nar_hash('sha256:'+'z'*52)

    def test_approved_upstream_only_after_explicit_primary_absence(self):
        calls=[]
        def read(url):
            calls.append(url)
            return (404,b'') if url.startswith('https://maestro.') else (200,BODY)
        value=d.cache(PRODUCT,'https://maestro.cachix.org',read,('https://cache.nixos.org',))
        self.assertEqual(value['status'],'verified')
        self.assertEqual(len(calls),2)
        self.assertEqual(d.receipt(value,PRODUCT)['expected'],{P:H})
        for status,body,state in [(503,b'','unavailable'),(200,BODY.replace(b'NarSize: 1',b'NarSize: 0'),'conflict')]:
            calls.clear()
            def fail_primary(url):
                calls.append(url)
                return status,body
            value=d.cache(PRODUCT,'https://maestro.cachix.org',fail_primary,('https://cache.nixos.org',))
            self.assertEqual(value['status'],state)
            self.assertEqual(len(calls),1)
            with self.assertRaises(ValueError):d.receipt(value,PRODUCT)

    def test_upstream_identity_conflicts_unavailable_and_all_absent_block(self):
        for status,body,state in [(404,b'','missing'),(503,b'','unavailable'),
                                 (200,BODY.replace(b'NarSize: 1',b'NarSize: 0'),'conflict')]:
            def read(url):return (404,b'') if url.startswith('https://maestro.') else (status,body)
            value=d.cache(PRODUCT,'https://maestro.cachix.org',read,('https://cache.nixos.org',))
            self.assertEqual(value['status'],state)
            with self.assertRaises(ValueError):d.receipt(value,PRODUCT)
        for sources in [('https://attacker.example',),('https://cache.nixos.org',)*2,('https://maestro.cachix.org',)]:
            with self.assertRaises(ValueError):d.cache(PRODUCT,'https://maestro.cachix.org',upstreams=sources)
        with self.assertRaises(ValueError):d.cache(PRODUCT,'https://xen-orchestra-ce.cachix.org',upstreams=('https://cache.nixos.org',))

    def test_recursive_missing_child_prevents_root_only_receipt(self):
        child='/nix/store/'+'1'*32+'-child'
        body=BODY.replace(b'References: ', ('References: '+Path(child).name).encode())
        calls=[]
        def read(url):
            calls.append(url)
            return (200,body) if Path(P).name[:32] in url else (404,b'')
        value=d.cache(PRODUCT,'https://maestro.cachix.org',read,('https://cache.nixos.org',))
        self.assertEqual(value['status'],'partial')
        self.assertEqual(value['expected'],value['observed'])
        self.assertEqual(value['missing'],[child])
        self.assertEqual(value['closure']['inspectedPaths'],2)
        with self.assertRaises(ValueError):d.receipt(value,PRODUCT)

    def test_recursive_upstream_cycles_and_shared_paths_are_read_once(self):
        child='/nix/store/'+'1'*32+'-child'
        bodies={P:BODY.replace(b'References: ',('References: '+Path(child).name+' '+Path(P).name).encode()),
                child:BODY.replace(P.encode(),child.encode()).replace(b'References: ',('References: '+Path(P).name).encode())}
        calls=[]
        def read(url):
            calls.append(url)
            path=next(p for p in bodies if Path(p).name[:32] in url)
            return (404,b'') if path==child and url.startswith('https://maestro.') else (200,bodies[path])
        value=d.cache(PRODUCT,'https://maestro.cachix.org',read,('https://cache.nixos.org',))
        self.assertEqual(value['status'],'verified');self.assertEqual(len(calls),3)
        self.assertEqual(value['closure']['inspectedPaths'],2)

    def test_retained_closure_seeds_missing_roots_and_rejects_foreign_or_conflicting_children(self):
        child='/nix/store/'+'1'*32+'-child'
        closure={P:{'narHash':H},child:{'narHash':H}}
        calls=[]
        def absent(url):calls.append(url);return 404,b''
        value=d.cache(PRODUCT,'https://maestro.cachix.org',absent,closure=closure)
        self.assertEqual(set(value['missing']),set(closure));self.assertEqual(len(calls),2)
        body=BODY.replace(b'References: ',('References: '+Path(child).name).encode())
        def read(url):return (200,body) if Path(P).name[:32] in url else (200,BODY.replace(P.encode(),child.encode()))
        self.assertEqual(d.cache(PRODUCT,'https://maestro.cachix.org',read,closure={P:{'narHash':H}})['status'],'conflict')
        closure[child]['narHash']='sha256-'+base64.b64encode(bytes([1])*32).decode()
        self.assertEqual(d.cache(PRODUCT,'https://maestro.cachix.org',read,closure=closure)['status'],'conflict')

    def test_recursive_primary_outage_is_not_masked_and_malformed_references_block(self):
        child='/nix/store/'+'1'*32+'-child'
        parent=BODY.replace(b'References: ',('References: '+Path(child).name).encode())
        calls=[]
        def read(url):
            calls.append(url)
            return (200,parent) if Path(P).name[:32] in url else (503,b'')
        self.assertEqual(d.cache(PRODUCT,'https://maestro.cachix.org',read,('https://cache.nixos.org',))['status'],'unavailable')
        self.assertEqual(len(calls),2)
        for reference in ('../escape','/nix/store/'+Path(child).name,Path(child).name+' '+Path(child).name,
                          '1'*32+'-'+'x'*212):
            bad=BODY.replace(b'References: ',('References: '+reference).encode())
            with self.assertRaises(ValueError):d.cache(PRODUCT,'https://maestro.cachix.org',lambda _:(200,bad))
        self.assertEqual(d.cache(PRODUCT,'https://maestro.cachix.org',
            lambda _:(200,BODY.replace(b'References: \n',b'')))['status'],'verified')
        with patch.object(d,'MAX_CACHE_PATHS',1):
            with self.assertRaises(ValueError):d.cache(PRODUCT,'https://maestro.cachix.org',lambda _:(200,parent))

    def test_worker_uses_parent_absolute_deadline(self):
        import time
        child='/nix/store/'+'1'*32+'-child'
        deadline=[]
        def read(url):
            deadline.append(d.operations.DEADLINE.get())
            time.sleep(0.03)
            return 200,BODY.replace(b'References: ',('References: '+Path(child).name).encode())
        with d.operations.budget(0.01) as parent:
            value=d.cache(PRODUCT,'https://maestro.cachix.org',read)
        self.assertEqual(deadline,[parent]);self.assertEqual(value['status'],'unavailable')

    def test_flakehub_verifies_exact_pinned_revision_without_source_download(self):
        location='https://api.flakehub.com/f/pinned/closure-labs/maestro/3.0.0/uuid/source.tar.gz'
        calls=[]
        def read(url,head):
            calls.append((url,head))
            return 307,((f'Location: {location}\r\n' if len(calls)==1 else
                        f'Link: <{location}?rev={PRODUCT["revision"]}&revCount=1>; rel="immutable"\r\n').encode())
        self.assertEqual(d.flakehub('3.0.0',PRODUCT['revision'],read)['status'],'verified')
        self.assertTrue(all(head for _,head in calls));self.assertEqual(len(calls),2)
        self.assertEqual(d.flakehub('3.0.0',PRODUCT['revision'],lambda *a,**k:(404,b''))['status'],'missing')
        self.assertEqual(d.flakehub('3.0.0',PRODUCT['revision'],lambda *a,**k:(503,b''))['status'],'unavailable')

if __name__=='__main__':unittest.main()
