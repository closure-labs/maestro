#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One explicit standard-review risk artifact; no chain, registry or newest selector."""
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PATH = 'automation/security-risk-acceptance.json'
KIND = 'explicit-findings-risk-acceptance'
MAX_DAYS = 30


def require(value, message):
    if not value:raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()


def fingerprints(rows):
    return sorted(digest(row) for row in rows)


def policy_bytes(path):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=1024**2,'Bounded regular verifier/policy file required')
        raw=stream.read(1024**2+1);require(len(raw)==info.st_size,'Verifier/policy changed during read')
        return raw


def policy_context(files):
    return digest({name:hashlib.sha256(policy_bytes(path)).hexdigest() for name,path in files.items()})


def scope(bundle, findings, files):
    product=bundle['product']
    roots={group:{name:{k:row[k] for k in ('storePath','narHash')} for name,row in product[group].items()} for group in ('products','roots')}
    return dict(productRootsSha256=digest(roots),securityContextSha256=digest(bundle['native']['securityContext']),
        inventoryDocumentsSha256=digest(bundle['binding']['evidenceFiles']),
        rawFindingSetSha256=digest(fingerprints(findings)),
        normalizedFindingSetSha256=digest(fingerprints(bundle['normalizedFindings'])),
        verificationPolicySha256=policy_context(files))


def owners(raw):
    lines=[line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    require(len(lines)==1,'Risk review requires the reviewed global CODEOWNERS contract')
    tokens=lines[0].split();require(tokens[0]=='*' and len(tokens)>1,'Global CODEOWNERS required')
    require(all(re.fullmatch(r'@[A-Za-z0-9][A-Za-z0-9-]*',v) for v in tokens[1:]),'Human CODEOWNER logins required')
    return {v[1:].lower() for v in tokens[1:]}


def contents(api,path,revision):
    row=api('contents/'+path+'?ref='+revision)
    require(row.get('encoding')=='base64' and type(row.get('size')) is int and 0<row['size']<=1024**2,'Bounded reviewed source document required')
    raw=base64.b64decode(row['content'],validate=False)
    require(len(raw)==row['size'],'Source document size mismatch')
    return raw


def review(api,record,record_hash,revision,eligible):
    number=record['reviewPullRequest'];require(type(number) is int and number>0,'Exact findings-review PR required')
    pr=api(f'pulls/{number}')
    require(pr.get('number')==number and pr.get('merged_at') and pr.get('state')=='closed'
        and pr.get('base',{}).get('ref')=='main'
        and pr.get('base',{}).get('repo',{}).get('full_name')=='closure-labs/maestro'
        and pr.get('head',{}).get('repo',{}).get('full_name')=='closure-labs/maestro'
        and pr.get('changed_files')==1 and pr.get('title','').startswith('security: accept findings risk'),
        'Only a merged dedicated findings-risk PR may accept risk')
    head=pr['head']['sha'];require(re.fullmatch('[0-9a-f]{40}',head),'Exact reviewed head required')
    files=api(f'pulls/{number}/files?per_page=2')
    require(len(files)==1 and files[0].get('filename')==PATH and files[0].get('status') in ('added','modified'),
        'Findings-risk PR may change only the risk artifact')
    require(digest(parse(contents(api,PATH,head)))==record_hash,'Risk artifact differs from reviewed PR head')
    merge=pr.get('merge_commit_sha','');require(re.fullmatch('[0-9a-f]{40}',merge),'Merged risk decision required')
    comparison=api(f'compare/{merge}...{revision}')
    require(comparison.get('merge_base_commit',{}).get('sha')==merge,'Risk decision is not on current main history')
    rows=[]
    for page in range(1,6):
        values=api(f'pulls/{number}/reviews?per_page=100&page={page}');rows.extend(values)
        if len(values)<100:break
    else:raise ValueError('Risk-review inventory exceeds bound')
    latest={}
    for row in rows:
        if row.get('state') in ('APPROVED','CHANGES_REQUESTED','DISMISSED'):
            uid=row.get('user',{}).get('id');rid=row.get('id')
            require(type(uid) is int and type(rid) is int and rid>0,'Invalid review identity')
            if rid>latest.get(uid,{}).get('id',0):latest[uid]=row
    for row in latest.values():
        user=row.get('user',{})
        if (row.get('state')=='APPROVED' and row.get('commit_id')==head
                and user.get('type')=='User' and type(user.get('id')) is int and user['id']>0
                and user.get('login','').lower() in eligible and user['id']!=pr.get('user',{}).get('id')):
            return dict(pullRequest=number,reviewId=row['id'],reviewedHead=head,reviewer=user['login'])
    raise ValueError('Explicit independent human findings-risk approval missing, stale or revoked')


def parse(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'Duplicate risk artifact key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite risk artifact')))


def load_local(path):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=1024**2,'Bounded regular risk artifact required')
        raw=stream.read(1024**2+1);require(len(raw)==info.st_size,'Risk artifact changed during read')
    return parse(raw)


def acceptance(bundle,findings,raw_blocking,normalized_blocking,files,api,root):
    local=Path(root)/PATH
    if not local.exists():return None
    record=load_local(local);record_hash=digest(record);revision=bundle['receipt']['sourceRevision']
    require(digest(parse(contents(api,PATH,revision)))==record_hash,'Risk artifact is not exact protected current source')
    required={'schemaVersion','kind','repository','reviewPullRequest','createdAt','expiresAt','reason','evidence',
              'scope','acceptedRawFindings','acceptedNormalizedFindings'}
    require(isinstance(record,dict) and set(record)==required and type(record['schemaVersion']) is int
        and record['schemaVersion']==1 and record['kind']==KIND and record['repository']=='closure-labs/maestro',
        'Invalid explicit findings-risk artifact')
    require(isinstance(record['reason'],str) and 0<len(record['reason'].strip())<=4000
        and isinstance(record['evidence'],list) and 0<len(record['evidence'])<=20
        and all(isinstance(v,str) and v.startswith('https://') and len(v)<=2048 for v in record['evidence']),
        'Risk acceptance requires an explicit rationale and reviewable evidence')
    require(all(isinstance(record[k],str) for k in ('createdAt','expiresAt')),'Explicit risk timestamps required')
    created=datetime.fromisoformat(record['createdAt'].replace('Z','+00:00'));expires=datetime.fromisoformat(record['expiresAt'].replace('Z','+00:00'));now=datetime.now(timezone.utc)
    require(created.tzinfo is not None and expires.tzinfo is not None and created<=now<expires
        and timedelta()<expires-created<=timedelta(days=MAX_DAYS),'Expired, future or over-30-day risk acceptance')
    require(record['scope']==scope(bundle,findings,files),'Changed/new findings, product, context, inventory or verification policy need new risk review')
    raw=set(fingerprints(raw_blocking));normalized=set(fingerprints(normalized_blocking))
    for field,present in [('acceptedRawFindings',raw),('acceptedNormalizedFindings',normalized)]:
        accepted=record[field]
        require(isinstance(accepted,list) and all(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) for v in accepted)
            and accepted==sorted(set(accepted)) and set(accepted)<=present,'Risk acceptance exceeds exact present finding scope')
    for name,path in files.items():
        require(hashlib.sha256(contents(api,name,revision)).hexdigest()==hashlib.sha256(policy_bytes(path)).hexdigest(),
            'Risk verifier/policy differs from protected source: '+name)
    eligible=owners(contents(api,'.github/CODEOWNERS',revision).decode())
    proof=review(api,record,record_hash,revision,eligible)
    return dict(record=record,recordHash=record_hash,proof=proof,eligible=eligible,expires=expires,
        raw=set(record['acceptedRawFindings']),normalized=set(record['acceptedNormalizedFindings']))


def live(api,state,revision):
    require(datetime.now(timezone.utc)<state['expires'],'Risk acceptance expired before operation')
    # Only this one exact risk review is mutable. No historic graph, App-admin
    # replay, newest selection or org membership credential is used.
    return review(api,state['record'],state['recordHash'],revision,state['eligible'])
