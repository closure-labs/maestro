# SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only destination identity reconciliation. Never grants authority."""
import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from collections import deque
from contextvars import copy_context
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlparse, parse_qs, quote
import operations
import diagnostics

ALPHABET='0123456789abcdfghijklmnpqrsvwxyz'
STORE = re.compile(r'/nix/store/['+ALPHABET+r']{32}-[A-Za-z0-9+._?=-]{1,211}')
MAX_CACHE_PATHS = 10_000
MAX_CACHE_EDGES = 100_000
CACHE_WORKERS = 8


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def nar_hash(value):
    if re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=', value):
        raw=base64.b64decode(value[7:], validate=True)
    elif re.fullmatch(r'sha256:['+ALPHABET+r']{52}', value):
        number=sum(ALPHABET.index(c) << (5*i) for i,c in enumerate(reversed(value[7:])))
        if number >= 1 << 256:
            raise ValueError('Invalid NAR hash')
        raw=number.to_bytes(32,'little')
    else:
        raise ValueError('Invalid NAR hash')
    return 'sha256-'+base64.b64encode(raw).decode()


@diagnostics.requests.public
def http(url, head=False):
    # Only caller-constructed, credential-free public endpoints are accepted.
    parsed=urlparse(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Invalid public destination URL')
    with tempfile.TemporaryDirectory(prefix='destination-read-') as temp:
        body=Path(temp)/'body'
        args=['curl','--silent','--show-error','--proto','=https','--max-time','30',
              '--connect-timeout','5','--retry','1','--retry-delay','0','--retry-max-time','25',
              '--max-filesize',str(2*1024*1024),'--user-agent','Nix/2.34',
              '--output',str(body),'--write-out','%{http_code}']
        if head:
            args+=['--head']
        diagnostics.count('publicTransportInvocations')
        diagnostics.profile('transport', 'public-http', wrappers=1)
        result=operations.run([*args,url], capture_output=True, text=True, timeout=30, check=False)
        if body.exists():
            diagnostics.profile('transport', 'public-http', captured=body.stat().st_size)
        if result.returncode or not re.fullmatch(r'[0-9]{3}',result.stdout):
            return None,b''
        data=body.read_bytes() if body.exists() else b''
        if len(data)>2*1024*1024:
            return None,b''
        return int(result.stdout),data


def result(destination, expected, observed, missing=(), unavailable=False):
    conflict=any(key in observed and canonical(observed[key]) != canonical(value) for key,value in expected.items())
    state=('conflict' if conflict else 'unavailable' if unavailable else
           'verified' if not missing else 'partial' if observed else 'missing')
    return {'schema':1,'destination':destination,'status':state,'expected':expected,
            'observed':observed,'missing':sorted(missing),'authorityClaim':False}


def closure_identities(records, expected):
    if isinstance(records, list):
        if any(not isinstance(record, dict) or not isinstance(record.get('path'), str) for record in records):
            raise ValueError('Invalid local closure records')
        if len({record['path'] for record in records}) != len(records):
            raise ValueError('Duplicate local closure paths')
        records = {record['path']: record for record in records}
    if not isinstance(records, dict) or not records or len(records) > MAX_CACHE_PATHS:
        raise ValueError('Invalid local closure inventory')
    identities = {}
    for path, record in records.items():
        if not isinstance(path, str) or not STORE.fullmatch(path) or not isinstance(record, dict):
            raise ValueError('Invalid local closure path')
        identities[path] = nar_hash(record.get('narHash', ''))
    if any(identities.get(path) != digest for path, digest in expected.items()):
        raise ValueError('Local closure differs from approved roots')
    return identities


def _cache(product, url, read=http, upstreams=(), closure=None):
    if url not in ('https://maestro.cachix.org','https://xen-orchestra-ce.cachix.org'):
        raise ValueError('Unknown public cache')
    if (len(upstreams)!=len(set(upstreams)) or any(source not in
            ('https://cache.nixos.org','https://xen-orchestra-ce.cachix.org') or source==url
            for source in upstreams) or (upstreams and url!='https://maestro.cachix.org')):
        raise ValueError('Unknown public cache upstream')
    expected={}
    for entry in [*product['products'].values(),*product.get('roots',{}).values()]:
        path=entry['storePath']
        if not isinstance(path, str) or not STORE.fullmatch(path):
            raise ValueError('Invalid approved store path')
        digest=nar_hash(entry['narHash'])
        if path in expected and expected[path] != digest:
            raise ValueError('Conflicting approved root identities')
        expected[path]=digest
    if not expected:
        raise ValueError('Empty cache inventory')
    identities = closure_identities(closure, expected) if closure is not None else expected
    if len(identities) > MAX_CACHE_PATHS:
        raise ValueError('Public cache closure exceeds metadata bounds')
    observed = {}; missing = []; unavailable = False; conflict = False
    seen = set(); discovered = set(identities); frontier = deque(sorted(identities)); edges = 0

    def inspect(path):
        diagnostics.requests.inspected_path()
        try:
            status, body = 404, b''
            for depth, source in enumerate((url, *upstreams)):
                origin = 'primary' if source == url else 'nixos-upstream' if source == 'https://cache.nixos.org' else 'xo-upstream'
                with diagnostics.requests.scope(purpose='cache-metadata', origin=origin, method='GET', fallback=str(depth)):
                    try:
                        status, body = read(source+'/'+Path(path).name[:32]+'.narinfo')
                    except BaseException:
                        diagnostics.requests.cache_response(None)
                        raise
                    diagnostics.requests.cache_response(status)
                if status != 404:
                    break
        except subprocess.TimeoutExpired:
            return path, None, None, ()
        if status != 200:
            return path, status, None, ()
        fields = {}
        for line in body.decode('utf-8').splitlines():
            key, sep, value = line.partition(': ')
            if not sep or (key in fields and key != 'Sig'):
                raise ValueError('Malformed public cache metadata')
            fields[key] = value
        if (fields.get('StorePath') != path or not fields.get('URL')
                or not re.fullmatch(r'[1-9][0-9]*', fields.get('NarSize', ''))):
            return path, status, 'invalid-metadata', ()
        digest = nar_hash(fields.get('NarHash', ''))
        # Native Nix also treats an omitted References field as an empty set.
        references = fields.get('References', '').split()
        if len(references) > MAX_CACHE_PATHS or len(references) != len(set(references)):
            raise ValueError('Invalid public cache references')
        children = tuple('/nix/store/'+value for value in references)
        if any(not STORE.fullmatch(child) for child in children):
            raise ValueError('Invalid public cache reference path')
        return path, status, digest, children

    # Copy the absolute deadline to workers. Keep at most eight reads active,
    # replenish completed slots, and queue every root before discovered children.
    with operations.budget(120), operations.cancellation_scope() as cancelled:
        pool = ThreadPoolExecutor(max_workers=CACHE_WORKERS)
        pending = set()
        try:
            while (frontier or pending) and not unavailable:
                try:
                    limit = operations.remaining(120)
                except subprocess.TimeoutExpired:
                    unavailable = True
                    break
                while frontier and len(pending) < CACHE_WORKERS:
                    pending.add(pool.submit(copy_context().run, inspect, frontier.popleft()))
                completed, _ = wait(pending, timeout=limit, return_when=FIRST_COMPLETED)
                if not completed:
                    unavailable = True
                    break
                pending.difference_update(completed)
                for future in completed:
                    path, status, digest, children = future.result()
                    seen.add(path)
                    if status == 404:
                        missing.append(path)
                    elif status != 200:
                        unavailable = True
                    else:
                        if path in expected:
                            observed[path] = digest
                        conflict |= digest == 'invalid-metadata' or (path in identities and identities[path] != digest)
                        if closure is not None and any(child not in identities for child in children):
                            conflict = True
                        edges += len(children)
                        for child in children:
                            if child not in discovered:
                                discovered.add(child)
                                frontier.append(child)
                        if len(discovered) > MAX_CACHE_PATHS or edges > MAX_CACHE_EDGES:
                            raise ValueError('Public cache closure exceeds metadata bounds')
        finally:
            cancelled.set()
            pool.shutdown(wait=True, cancel_futures=True)
    value = result('cache', expected, observed, missing, unavailable)
    if conflict:
        value['status'] = 'conflict'
    value['closure'] = {'inspectedPaths': len(seen), 'missingPaths': len(missing)}
    return value


@diagnostics.requests.cache_inspection
def cache(product, url, read=http, upstreams=(), closure=None):
    import public_cache_transport
    selected = public_cache_transport.enabled()
    if selected and read is http:
        with public_cache_transport.Reader(CACHE_WORKERS) as reader:
            return _cache(product, url, read=reader, upstreams=upstreams, closure=closure)
    return _cache(product, url, read=read, upstreams=upstreams, closure=closure)


def flakehub(version, revision, read=http):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:\+rev-[0-9a-f]{40})?',version) or not re.fullmatch(r'[0-9a-f]{40}',revision):
        raise ValueError('Invalid immutable FlakeHub identity')
    expected={'version':version,'revision':revision}; observed={}
    status,body=read('https://api.flakehub.com/f/closure-labs/maestro/'+quote('='+version,safe=''),head=True)
    if status==404:
        return result('flakehub',expected,observed,expected)
    if status != 307:
        return result('flakehub',expected,observed,unavailable=True)
    headers=body.decode().splitlines()
    locations=[line.split(':',1)[1].strip() for line in headers if line.lower().startswith('location:')]
    if len(locations)!=1:
        raise ValueError('Invalid FlakeHub immutable location')
    location=urlparse(locations[0]); segments=location.path.split('/')
    if location.scheme!='https' or location.netloc!='api.flakehub.com' or segments[:5]!=['','f','pinned','closure-labs','maestro'] or len(segments)!=8 or segments[-1]!='source.tar.gz':
        raise ValueError('Unexpected FlakeHub immutable identity')
    observed['version']=segments[5]
    status,body=read(locations[0],head=True)
    if status!=307:
        return result('flakehub',expected,observed,unavailable=True)
    links=[line.split(':',1)[1].strip() for line in body.decode().splitlines() if line.lower().startswith('link:')]
    if len(links)!=1:
        raise ValueError('Missing FlakeHub revision proof')
    match=re.fullmatch(r'<([^>]+)>; rel="immutable"',links[0])
    if not match:
        raise ValueError('Invalid FlakeHub revision proof')
    proof=urlparse(match[1]); values=parse_qs(proof.query)
    if proof.scheme!='https' or proof.netloc!=location.netloc or proof.path!=location.path or len(values.get('rev',[]))!=1:
        raise ValueError('FlakeHub immutable source differs')
    observed['revision']=values['rev'][0]
    return result('flakehub',expected,observed)


def receipt(value, product):
    if value['status']!='verified' or canonical(value['expected'])!=canonical(value['observed']):
        raise ValueError('Destination has no current verification proof')
    return {'schema':1,'destination':value['destination'],'productHash':hashlib.sha256(canonical(product)).hexdigest(),
            'status':'verified','expected':value['expected'],'observed':value['observed'],
            'verifiedAt':dt.datetime.now(dt.timezone.utc).isoformat(),'verifier':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


@diagnostics.staged
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',choices=['cache','flakehub'])
    parser.add_argument('--product',required=True,type=Path)
    parser.add_argument('--cache-url')
    parser.add_argument('--closure-metadata', type=Path)
    parser.add_argument('--upstream-cache-url',action='append',default=[])
    parser.add_argument('--version')
    parser.add_argument('--require-verified',action='store_true')
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--output', type=Path)
    args=parser.parse_args(); product=json.loads(args.product.read_text())
    closure = None
    if args.closure_metadata:
        if args.closure_metadata.stat().st_size > 64*1024*1024:
            raise ValueError('Local closure metadata exceeds byte bound')
        closure = json.loads(args.closure_metadata.read_bytes())
    value=cache(product,args.cache_url,upstreams=args.upstream_cache_url,closure=closure) if args.destination=='cache' else flakehub(args.version,product['revision'])
    # Persist the exact structured observation even when the verdict is blocked.
    raw = json.dumps(value, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(raw)
    context = {'productHash': hashlib.sha256(canonical(product)).hexdigest()} if diagnostics.enabled() else None
    print(diagnostics.record(value, 'destinations', context=context) or raw, end='')
    if value['status'] in ('conflict','unavailable') or (args.require_verified and value['status']!='verified'):
        raise SystemExit('Public destination '+value['status'])
    if args.receipt and value['status']=='verified':
        args.receipt.write_bytes(canonical(receipt(value,product))+b'\n')


if __name__=='__main__':
    main()
