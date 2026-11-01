#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inspect one reviewed interrupted packet write; never create decision authority."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import decision_packets as packets
from decision_authority import github_api
import operations
from security_decisions import canonical_hash

REPOSITORY = 'closure-labs/maestro'
REPOSITORY_ID = 1127149753
REQUEST_HASH = 'f342d0b3f3666219d87a6ad9bc27f529929c322247c4e290b83710065bdfbf51'
REQUEST_PATH = Path(__file__).with_name('packet-inspection-request.json')
REGISTRY = 'ghcr.io/closure-labs/maestro-decisions'
MAX_REQUEST = 16 * 1024
MAX_LOG = 2 * 1024**2


def require(value):
    if not value:
        raise ValueError('Packet inspection binding or resource limit failed')


def reviewed_request(raw, confirmation):
    require(len(raw) <= MAX_REQUEST)
    value = packets.decode_json(raw)
    require(confirmation == REQUEST_HASH and canonical_hash(value) == REQUEST_HASH)
    require(set(value) == {'schema', 'originalRun', 'artifact', 'descriptor',
                          'descriptorSha256', 'descriptorBlobSha256', 'descriptorBytes'} and value['schema'] == 1)
    descriptor = value['descriptor']
    require(set(descriptor) == {'schema', 'producer', 'files'} and descriptor['schema'] == 1)
    files = descriptor['files']
    require(isinstance(files, dict) and len(files) == 22 and 'decision-packet.json' not in files)
    for name, record in files.items():
        require(packets.safe_name(name) == name and set(record) == {'sha256', 'size'}
                and isinstance(record['sha256'], str) and re.fullmatch('[0-9a-f]{64}', record['sha256'])
                and type(record['size']) is int and 0 < record['size'] <= 2 * 1024**3)
    require(sum(x['size'] for x in files.values()) <= 4 * 1024**3)
    raw_descriptor = (json.dumps(descriptor, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(canonical_hash(descriptor) == value['descriptorSha256']
            and hashlib.sha256(raw_descriptor).hexdigest() == value['descriptorBlobSha256']
            and len(raw_descriptor) == value['descriptorBytes'] <= 16 * 1024)
    return value, raw_descriptor


def run_binding(value, identity, attempt, revision, workflow, event, conclusion):
    require(isinstance(value, dict) and value.get('id') == identity and value.get('run_attempt') == attempt
            and value.get('head_sha') == revision and value.get('head_branch') == 'main'
            and value.get('path') == workflow and value.get('event') == event
            and value.get('status') == 'completed' and value.get('conclusion') == conclusion
            and all((value.get(k) or {}).get('id') == REPOSITORY_ID
                    and (value.get(k) or {}).get('full_name') == REPOSITORY
                    for k in ('repository', 'head_repository')))


def authenticate(request):
    """Bind the old request to exact-attempt API metadata and retained job logs."""
    prefix = f'repos/{REPOSITORY}/actions'
    old, producer = request['originalRun'], request['descriptor']['producer']
    original = github_api(f'{prefix}/runs/{old["id"]}/attempts/{old["attempt"]}')
    run_binding(original, old['id'], old['attempt'], old['revision'],
                '.github/workflows/decisions.yml', 'workflow_dispatch', 'cancelled')
    source = github_api(f'{prefix}/runs/{producer["runId"]}/attempts/{producer["runAttempt"]}')
    run_binding(source, producer['runId'], producer['runAttempt'], producer['revision'],
                '.github/workflows/ci.yml', 'push', 'success')
    require(producer == {'repository': REPOSITORY, 'revision': old['revision'], 'sourceRevision': old['revision'],
                        'workflow': '.github/workflows/ci.yml', 'signerWorkflow': '.github/workflows/ci.yml',
                        'runId': 41262202226, 'runAttempt': 1})
    job = github_api(f'{prefix}/jobs/{old["job"]}')
    require(job.get('id') == old['job'] and job.get('run_id') == old['id']
            and job.get('run_attempt') == old['attempt'] and job.get('head_sha') == old['revision']
            and job.get('head_branch') == 'main' and job.get('name') == 'reconcile'
            and job.get('status') == 'completed')
    raw = packets.command(['gh', 'api', '--method', 'GET', '--allow-escape-sequences',
                           f'{prefix}/jobs/{old["job"]}/logs'])
    require(len(raw) <= MAX_LOG)
    lines = raw.decode('utf-8').splitlines()
    requests = [line.split('SECURITY_RECOVERY_REQUEST: ', 1)[1]
                for line in lines if re.match(r'^\S+\s+SECURITY_RECOVERY_REQUEST: ', line)]
    candidates = [line.rsplit('CANDIDATE_RUN: ', 1)[1]
                  for line in lines if re.match(r'^\S+\s+CANDIDATE_RUN: ', line)]
    require(len(requests) == len(candidates) == 1 and candidates[0] == str(producer['runId'])
            and packets.decode_json(requests[0].encode()) == old['recovery'])
    artifact = github_api(f'{prefix}/artifacts/{request["artifact"]["id"]}')
    expected = request['artifact']
    require(artifact.get('id') == expected['id'] and artifact.get('name') == 'maestro-security-report'
            and artifact.get('expired') is False and artifact.get('digest') == expected['archiveSha256']
            and artifact.get('size_in_bytes') == expected['archiveBytes']
            and (artifact.get('workflow_run') or {}).get('id') == producer['runId']
            and (artifact.get('workflow_run') or {}).get('head_sha') == producer['revision'])


def inspect(request, descriptor_bytes):
    authenticate(request)
    require(packets.REGISTRY == REGISTRY)
    packets.private_review_registry()  # Positive private-package read; no bootstrap default.
    tag = REGISTRY + ':packet-' + request['descriptorSha256']
    raw = packets.command(['oras', 'manifest', 'fetch', tag])
    require(len(raw) <= 2 * 1024**2)
    reference = REGISTRY + '@sha256:' + hashlib.sha256(raw).hexdigest()
    members = packets.manifest_members(reference, raw)
    expected = dict(request['descriptor']['files'], **{'decision-packet.json': {
        'sha256': request['descriptorBlobSha256'], 'size': request['descriptorBytes']}})
    require(members == expected)
    # Re-fetch by immutable digest. Existing bounded verifier authenticates the
    # complete inventory and producer; only the descriptor blob is downloaded.
    readback = packets.metadata_bytes(reference, request['descriptorSha256'], 'decision-packet.json',
                                      producer=request['descriptor']['producer'])
    require(readback == descriptor_bytes)
    return {'schema': 1, 'status': 'verified-existing', 'authorization': False,
            'requestSha256': REQUEST_HASH, 'originalRun': request['originalRun']['id'],
            'originalAttempt': request['originalRun']['attempt'], 'artifact': request['artifact'],
            'producer': request['descriptor']['producer'], 'tag': tag, 'reference': reference,
            'descriptorSha256': request['descriptorSha256'], 'inventoryMembers': 22,
            'descriptorBytesVerified': len(readback), 'closurePayloadBytesDownloaded': 0}


def main():
    # Workflow gating is repeated here; direct invocation cannot select another
    # credential, target or write-capable mode. No fallback token is accepted.
    require(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_WORKFLOW_REF') ==
                REPOSITORY + '/.github/workflows/decision-packet-inspection.yml@refs/heads/main')
    token = os.environ.get('GITHUB_TOKEN')
    require(bool(token) and os.environ.get('GH_TOKEN') == token and os.environ.get('REGISTRY_TOKEN') == token)
    require(github_api(f'repos/{REPOSITORY}/branches/main').get('protected') is True)
    request, descriptor = reviewed_request(REQUEST_PATH.read_bytes(), os.environ.get('PACKET_INSPECTION_REQUEST_HASH'))
    output = Path(os.environ['RUNNER_TEMP']) / 'maestro-packet-inspection-receipt.json'
    result = {'schema': 1, 'status': 'unresolved', 'authorization': False, 'requestSha256': REQUEST_HASH}
    previous = os.environ.get('DOCKER_CONFIG')
    try:
        with operations.budget(240), tempfile.TemporaryDirectory(prefix='packet-inspection-') as directory:
            os.environ['DOCKER_CONFIG'] = directory
            packets.command(['oras', 'login', 'ghcr.io', '--username', os.environ['GITHUB_ACTOR'], '--password-stdin'],
                            input=token.encode())
            result = inspect(request, descriptor)
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired):
        # Never retain raw errors, credentials, logs or response bodies. Missing,
        # denied and transport failures all remain unresolved, never absent.
        raise ValueError('Read-only packet inspection unresolved; no absence or authority established') from None
    finally:
        if previous is None:
            os.environ.pop('DOCKER_CONFIG', None)
        else:
            os.environ['DOCKER_CONFIG'] = previous
        raw = json.dumps(result, sort_keys=True) + '\n'
        require(len(raw) <= 16 * 1024)
        output.write_text(raw)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
