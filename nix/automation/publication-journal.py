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

BRANCH = 'automation/publication-journals'
NAME = re.compile(r'[A-Za-z0-9_.+-]{1,128}')


class GitHubError(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def api(endpoint, method='GET', payload=None):
    args = ['gh', 'api', '--method', method, endpoint]
    if payload is not None:
        args += ['--input', '-']
    result = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                            capture_output=True, text=True, timeout=180)
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


def transition(repository, product_hash, key, step, state, authorize, github=api):
    common.require(NAME.fullmatch(key) and NAME.fullmatch(step), 'Invalid publication journal key or step')
    common.require(common.HASH.fullmatch(product_hash) and state in ('pending', 'complete'), 'Invalid publication journal state')
    branch(repository, authorize, github)
    endpoint = f'repos/{repository}/contents/publications/{key}.json'
    for attempt in range(4):
        sha = None
        try:
            remote = github(endpoint + '?ref=' + BRANCH)
            common.require(remote.get('type') == 'file' and remote.get('encoding') == 'base64'
                           and common.SHA.fullmatch(remote.get('sha', '')), 'Invalid journal contents response')
            sha = remote['sha']
            contents = base64.b64decode(''.join(remote['content'].split()), validate=True)
            document = json.loads(contents)
            validate(document, product_hash)
        except GitHubError as error:
            if error.status != 404:
                raise
            document = {'schema': 1, 'productHash': product_hash, 'steps': {}}
        previous = document['steps'].get(step)
        if previous == state or previous == 'complete':
            authorize()
            return document
        document['steps'][step] = state
        payload = {'message': f'Record {key} {step}: {state}', 'branch': BRANCH,
                   'content': base64.b64encode((json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode()).decode()}
        if sha:
            payload['sha'] = sha
        authorize()
        try:
            github(endpoint, 'PUT', payload)
            return document
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
    result = transition(cfg['repository'], product_hash, args.key, args.step, args.state, authorize)
    common.emit(result, args.output)


if __name__ == '__main__':
    sys.exit(common.run(main))
