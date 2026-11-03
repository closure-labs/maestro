#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One native environment findings review per exact first-attempt publication."""
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat

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


def parse(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'Duplicate risk artifact key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite risk artifact')))


ENVIRONMENT = 'findings-risk-review'
REPO_ID = 1127149753
REVIEWER_ID = 52590374
WORKFLOWS = {'publish': '.github/workflows/publication.yml',
             'release': '.github/workflows/release-publication.yml'}


def protected_files(api, files, revision):
    for name, path in files.items():
        row=api('contents/'+name+'?ref='+revision)
        require(row.get('encoding')=='base64' and type(row.get('size')) is int
            and 0<row['size']<=1024**2, 'Bounded protected risk policy required')
        raw=base64.b64decode(row['content'],validate=False)
        require(len(raw)==row['size'] and raw==policy_bytes(path),
            'Risk policy differs from exact protected source: '+name)


def runtime(api, revision, operation):
    require(operation in WORKFLOWS, 'Unsupported findings-review destination')
    run=os.environ.get('GITHUB_RUN_ID','')
    require(re.fullmatch('[1-9][0-9]*',run) and os.environ.get('GITHUB_RUN_ATTEMPT')=='1',
        'Fresh first-attempt publication run required; reruns cannot reuse review')
    require(os.environ.get('GITHUB_REPOSITORY')=='closure-labs/maestro'
        and os.environ.get('GITHUB_REF')=='refs/heads/main'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch'
        and os.environ.get('GITHUB_SHA')==revision, 'Protected publication context required')
    repository=api('')
    require(repository.get('id')==REPO_ID and repository.get('full_name')=='closure-labs/maestro'
        and repository.get('private') is False and repository.get('visibility')=='public',
        'Public repository required for GitHub Free environment protections')
    producer=api('actions/runs/'+run)
    require(producer.get('id')==int(run) and producer.get('run_attempt')==1
        and producer.get('head_sha')==revision and producer.get('head_branch')=='main'
        and producer.get('event')=='workflow_dispatch' and producer.get('path')==WORKFLOWS[operation]
        and producer.get('repository',{}).get('id')==REPO_ID
        and producer.get('status')=='in_progress', 'Publication run identity or attempt changed')
    created=datetime.fromisoformat(producer.get('created_at','').replace('Z','+00:00'))
    now=datetime.now(timezone.utc)
    require(created.tzinfo is not None and created<=now<created+timedelta(days=MAX_DAYS),
        'Publication approval window exceeds thirty days')
    require(api('git/ref/heads/main')['object']['sha']==revision,'Publication policy/main changed')
    return int(run)


def environment(api):
    value=api('environments/'+ENVIRONMENT)
    require(type(value.get('id')) is int and value['id']>0 and value.get('name')==ENVIRONMENT
        and value.get('can_admins_bypass') is False, 'Configured non-bypass findings environment required')
    require(value.get('deployment_branch_policy')==dict(protected_branches=True,custom_branch_policies=False),
        'Protected branch environment policy required')
    rules=value.get('protection_rules')
    require(isinstance(rules,list) and len(rules)==2
        and sorted(row.get('type','') for row in rules)==['branch_policy','required_reviewers'],
        'Exact branch and human-review environment rules required')
    rule=next(row for row in rules if row['type']=='required_reviewers')
    require(rule.get('prevent_self_review') is False,'Exact sole-maintainer review rule required')
    reviewers=rule.get('reviewers')
    require(isinstance(reviewers,list) and len(reviewers)==1 and reviewers[0].get('type')=='User'
        and reviewers[0].get('reviewer',{}).get('id')==REVIEWER_ID,
        'Configured eligible human findings reviewer required')
    return value['id']


def context(bundle, findings, files, operation, run):
    revision=bundle['receipt'].get('policyRevision',bundle['receipt']['sourceRevision'])
    return dict(schemaVersion=2,kind='per-publication-findings-risk-review',repositoryId=REPO_ID,
        runId=run,runAttempt=1,workflow=WORKFLOWS[operation],operation=operation,
        policyRevision=revision,productProducer=bundle['receipt'],
        healthProducer=bundle.get('healthManifest',{}).get('producer'),
        scanEvidenceSha256=digest(bundle['native']),scope=scope(bundle,findings,files))


def plan(bundle, findings, files, api, operation):
    revision=bundle['receipt'].get('policyRevision',bundle['receipt']['sourceRevision'])
    run=runtime(api,revision,operation);eid=environment(api)
    protected_files(api,files,revision)
    value=json.loads(json.dumps(context(bundle,findings,files,operation,run),allow_nan=False))
    return dict(context=value,contextSha256=digest(value),environmentId=eid)


def approval(api, state):
    require(not state.get('invalidated'), 'Observed failed review cannot revive after restoration')
    try:
        value=state['context']
        require(digest(value)==state['contextSha256'],'Frozen review context changed')
        run=runtime(api,value['policyRevision'],value['operation'])
        require(environment(api)==state['environmentId'],'Findings environment replaced')
        require(state['rebuild']()==value,'Changed findings, evidence, product or policy need fresh review')
        require(os.environ.get('NATIVE_FINDINGS_CONTEXT_SHA256')==state['contextSha256'],
            'Missing or changed protected pre-review context')
        rows=api('actions/runs/'+str(run)+'/approvals')
        require(isinstance(rows,list) and 0<len(rows)<=100,'Bounded native findings review history required')
        relevant=[row for row in rows if any(env.get('id')==state['environmentId']
            and env.get('name')==ENVIRONMENT for env in row.get('environments',[]))]
        # More than one decision is ambiguous; no newest-review selector or retry reuse.
        require(len(relevant)==1 and relevant[0].get('state')=='approved',
            'One explicit findings-risk approval for this run required')
        user=relevant[0].get('user',{})
        require(user.get('type')=='User' and user.get('id')==REVIEWER_ID
            and re.fullmatch('[A-Za-z0-9][A-Za-z0-9-]*',user.get('login','')),
            'Eligible human findings-risk approval required')
        permission=api('collaborators/'+user['login']+'/permission')
        require(permission.get('permission') in ('write','maintain','admin')
            and permission.get('user',{}).get('id')==REVIEWER_ID,
            'Findings reviewer no longer has required access')
        return dict(kind=value['kind'],runId=run,runAttempt=1,environmentId=state['environmentId'],
            reviewerId=REVIEWER_ID,contextSha256=state['contextSha256'])
    except Exception:
        state['invalidated']=True
        raise


def live(api,state,revision):
    try:
        require(revision==state['context']['policyRevision'],'Risk policy revision changed')
        return approval(api,state)
    except Exception:
        state['invalidated']=True
        raise
