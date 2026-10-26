#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reserve immutable publication identities and resume steps with GitHub SHA CAS."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, os.environ.get('MAESTRO_DECISIONS_SOURCE', str(Path(__file__).with_name('decisions'))))
import common
import publication_receipts
import destinations

BRANCH = 'automation/publication-journals'
NAME = re.compile(r'[A-Za-z0-9_.+-]{1,128}')


class GitHubError(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


@common.diagnostics.requests.github
def api(endpoint, method='GET', payload=None):
    common.require(os.environ.get('PUBLICATION_REQUIRE_VERIFIED') != 'true' or method == 'GET',
                   'Verified-only publication forbids GitHub mutations')
    common.diagnostics.count('apiWrapperInvocations')
    common.diagnostics.count('apiTransportInvocations')
    args = ['gh', 'api', '--method', method, endpoint]
    if payload is not None:
        args += ['--input', '-']
    # Retain this command's existing execution, timeout and failure semantics.
    # It does not use operations.run, so account for its transport here once.
    common.diagnostics.profile('transport', 'github-api', wrappers=1)
    with common.diagnostics.measuring('transport', 'github-api'):
        try:
            result = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                                    capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired as error:
            common.diagnostics.profile('transport', 'github-api', launches=1,
                                       captured=common.diagnostics.captured_bytes(error.stdout) + common.diagnostics.captured_bytes(error.stderr))
            raise
        common.diagnostics.profile('transport', 'github-api', launches=1,
                                   captured=common.diagnostics.captured_bytes(result.stdout) + common.diagnostics.captured_bytes(result.stderr))
    if result.returncode:
        status = re.search(r'\bHTTP (\d{3})\b', result.stderr)
        raise GitHubError(int(status[1]) if status else None, result.stderr.strip())
    return json.loads(result.stdout) if result.stdout.strip() else None


def branch(repository, authorize, github=api):
    endpoint = f'repos/{repository}/git/ref/heads/{BRANCH}'
    try:
        result = github(endpoint)
    except GitHubError as error:
        if error.status != 404:
            raise
        main = github(f'repos/{repository}/git/ref/heads/main')
        revision = main.get('object', {}).get('sha', '')
        common.require(common.SHA.fullmatch(revision), 'Invalid journal base revision')
        authorize()
        try:
            with common.diagnostics.requests.scope(purpose='journal-write'):
                github(f'repos/{repository}/git/refs', 'POST', {'ref': 'refs/heads/' + BRANCH, 'sha': revision})
        except GitHubError as conflict:
            if conflict.status not in (409, 422):
                raise
        result = github(endpoint)
    common.require(result.get('ref') == 'refs/heads/' + BRANCH and common.SHA.fullmatch(result.get('object', {}).get('sha', '')),
                   'Invalid journal branch identity')


def validate(document, product_hash):
    common.require(isinstance(document, dict) and set(document) == ({'schema', 'productHash', 'steps'}
                   if document.get('schema') == 1 else {'schema', 'productHash', 'steps', 'receipts'})
                   and document['schema'] in (1, 2) and document['productHash'] == product_hash,
                   'Publication key already reserved for a different immutable product')
    common.require(isinstance(document['steps'], dict) and all(NAME.fullmatch(k) and v in ('pending', 'complete') for k, v in document['steps'].items()),
                   'Malformed publication journal steps')
    receipts = publication_receipts.read(document, product_hash)
    common.require(all(document['steps'].get(name) == 'complete' for name in receipts),
                   'Receipt without completed destination')


def transition(repository, product_hash, key, step, state, authorize, github=api, receipt=None):
    """Standalone leaf retains independent authorization and bounded CAS retries."""
    for attempt in range(4):
        plan = prepare_transition(repository, product_hash, key, step, state, github, receipt)
        try:
            return write_prepared(plan, github, authorize=authorize)
        except GitHubError as error:
            if error.status not in (409, 422) or attempt == 3:
                raise
    raise ValueError('Journal compare-and-swap did not converge')


def main():
    parser = common.parser(__doc__)
    parser.add_argument('--product', required=True, type=Path)
    parser.add_argument('--scans', required=True, type=Path)
    parser.add_argument('--key', required=True)
    parser.add_argument('--step', required=True)
    parser.add_argument('--state', required=True, choices=['pending', 'complete'])
    parser.add_argument('--purpose', choices=['release', 'rolling'], default='release')
    args = parser.parse_args()
    cfg = common.config(args.config, live=True, enabled=True)
    product_hash = common.canonical_hash(common.load_json(args.product))
    def authorize():
        result = common.gate(cfg, args.scans, args.product, args.purpose)
        common.require(result.get('productHash') == product_hash, 'Product identity changed during publication')
    authorize()
    receipt = None
    if args.state == 'complete':
        receipt = common.load_json(Path(os.environ['PUBLICATION_RECEIPT']))
        publication_receipts.validate(receipt, product_hash, args.step)
    result = transition(cfg['repository'], product_hash, args.key, args.step, args.state, authorize, receipt=receipt)
    common.emit(result, args.output)


def prepare_transition(repository, product_hash, key, step, state, github=api, receipt=None):
    """Read and validate a proposed journal mutation, without granting authority."""
    common.require(NAME.fullmatch(key) and NAME.fullmatch(step), 'Invalid publication journal key or step')
    common.require(step != 'flakehub', 'FlakeHub publication has been removed')
    common.require(common.HASH.fullmatch(product_hash) and state in ('pending', 'complete'), 'Invalid publication journal state')
    if receipt is not None:
        publication_receipts.validate(receipt, product_hash, step)
        common.require(state == 'complete', 'Only verified completion accepts a receipt')
    branch_endpoint = f'repos/{repository}/git/ref/heads/{BRANCH}'
    create_branch = None
    try:
        observed = github(branch_endpoint)
        common.require(observed.get('ref') == 'refs/heads/' + BRANCH
                       and common.SHA.fullmatch(observed.get('object', {}).get('sha', '')), 'Invalid journal branch identity')
    except GitHubError as error:
        if error.status != 404:
            raise
        revision = github(f'repos/{repository}/git/ref/heads/main').get('object', {}).get('sha', '')
        common.require(common.SHA.fullmatch(revision), 'Invalid journal base revision')
        create_branch = {'ref': 'refs/heads/' + BRANCH, 'sha': revision}
    endpoint = f'repos/{repository}/contents/publications/{key}.json'
    sha = None
    try:
        remote = github(endpoint + '?ref=' + BRANCH)
        common.require(remote.get('type') == 'file' and remote.get('encoding') == 'base64'
                       and common.SHA.fullmatch(remote.get('sha', '')), 'Invalid journal contents response')
        sha = remote['sha']
        document = json.loads(base64.b64decode(''.join(remote['content'].split()), validate=True))
        validate(document, product_hash)
    except GitHubError as error:
        if error.status != 404:
            raise
        document = {'schema': 1, 'productHash': product_hash, 'steps': {}}
    previous = document['steps'].get(step)
    old_receipt = document.get('receipts', {}).get(step)
    same_proof = receipt is None or (old_receipt and all(old_receipt[k] == receipt[k] for k in ('expected', 'observed', 'verifier')))
    payload = None
    if not ((previous == state or previous == 'complete') and same_proof):
        document['steps'][step] = state
        if receipt is not None:
            document.update(schema=2, receipts={**document.get('receipts', {}), step: receipt})
        payload = {'message': f'Record {key} {step}: {state}', 'branch': BRANCH,
                   'content': base64.b64encode((json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode()).decode()}
        if sha:
            payload['sha'] = sha
    return {'repository': repository, 'branch': create_branch, 'endpoint': endpoint,
            'document': document, 'payload': payload}


def write_prepared(plan, github=api, authorize=None):
    """Apply a plan only inside the caller's freshly authorized write group.

    Conflicts/uncertain acknowledgements propagate. Callers must read back and
    obtain fresh authority before any further mutation; a plan is not authority.
    """
    common.require(os.environ.get('PUBLICATION_REQUIRE_VERIFIED') != 'true'
                   or (plan['branch'] is None and plan['payload'] is None),
                   'Verified-only publication requires an unchanged journal')
    repository = plan['repository']
    if authorize is not None and plan['branch'] is None and plan['payload'] is None:
        authorize()
    if plan['branch'] is not None:
        if authorize is not None:
            authorize()
        with common.diagnostics.requests.scope(purpose='journal-write'):
            github(f'repos/{repository}/git/refs', 'POST', plan['branch'])
        observed = github(f'repos/{repository}/git/ref/heads/{BRANCH}')
        common.require(observed.get('ref') == 'refs/heads/' + BRANCH
                       and common.SHA.fullmatch(observed.get('object', {}).get('sha', '')), 'Journal branch readback differs')
    if plan['payload'] is not None:
        if authorize is not None:
            authorize()
        github(plan['endpoint'], 'PUT', plan['payload'])
    # A no-op journal plan may precede tag/draft writes in the same group.
    # Read it back too: absence of a CAS write must not hide a changed binding.
    with common.diagnostics.requests.scope(purpose='journal-readback'):
        remote = github(plan['endpoint'] + '?ref=' + BRANCH)
    common.require(remote.get('encoding') == 'base64'
                   and json.loads(base64.b64decode(remote['content'])) == plan['document'],
                   'Publication journal readback differs from verified checkpoint')
    return plan['document']


if __name__ == '__main__':
    sys.exit(common.run(main))
