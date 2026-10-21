#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Journal CAS and immutable hosted-byte recovery; all GitHub calls are fake."""
import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).parents[1] / 'nix' / 'automation' / f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


journal = load('publication-journal')
assets = load('publication-assets')
SHA = 'a' * 40
OTHER = 'b' * 40
PRODUCT = 'c' * 64


def reject(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError('unsafe publication accepted')


class JournalAPI:
    def __init__(self):
        self.exists = False
        self.document = None
        self.sha = 'd' * 40
        self.conflict = False
        self.writes = 0

    def __call__(self, endpoint, method='GET', payload=None):
        if endpoint.endswith('/git/ref/heads/main'):
            return {'object': {'sha': SHA}}
        if endpoint.endswith('/git/ref/heads/' + journal.BRANCH):
            if not self.exists:
                raise journal.GitHubError(404, 'missing branch')
            return {'ref': 'refs/heads/' + journal.BRANCH, 'object': {'sha': SHA}}
        if endpoint.endswith('/git/refs') and method == 'POST':
            assert payload == {'ref': 'refs/heads/' + journal.BRANCH, 'sha': SHA}
            self.exists = True
            self.writes += 1
            return {}
        if '/contents/publications/' in endpoint:
            if method == 'GET':
                if self.document is None:
                    raise journal.GitHubError(404, 'missing journal')
                return {'type': 'file', 'encoding': 'base64', 'sha': self.sha,
                        'content': base64.b64encode(json.dumps(self.document).encode()).decode()}
            assert method == 'PUT' and payload['branch'] == journal.BRANCH
            if self.conflict:
                self.conflict = False
                self.document = {'schema': 1, 'productHash': PRODUCT, 'steps': {'other': 'complete'}}
                self.sha = 'e' * 40
                raise journal.GitHubError(409, 'simulated CAS conflict')
            assert payload.get('sha') == (self.sha if self.document else None)
            self.document = json.loads(base64.b64decode(payload['content']))
            self.writes += 1
            return {}
        raise AssertionError(endpoint)


calls = []
authorize = lambda: calls.append('live-gate')
api = JournalAPI()
first = journal.transition('owner/repo', PRODUCT, 'v1.2.3', 'assets', 'pending', authorize, api)
assert first['steps'] == {'assets': 'pending'} and api.writes == 2
journal.transition('owner/repo', PRODUCT, 'v1.2.3', 'assets', 'complete', authorize, api)
writes = api.writes
journal.transition('owner/repo', PRODUCT, 'v1.2.3', 'assets', 'pending', authorize, api)
assert api.writes == writes and api.document['steps']['assets'] == 'complete'
reject(lambda: journal.transition('owner/repo', 'f' * 64, 'v1.2.3', 'assets', 'complete', authorize, api))
reject(lambda: journal.transition('owner/repo', PRODUCT, '../escape', 'assets', 'pending', authorize, api))
api = JournalAPI()
api.conflict = True
retried = journal.transition('owner/repo', PRODUCT, 'v1.2.3', 'assets', 'complete', authorize, api)
assert retried['steps'] == {'other': 'complete', 'assets': 'complete'}


def blocked():
    raise ValueError('live authority revoked')

api = JournalAPI()
reject(lambda: journal.transition('owner/repo', PRODUCT, 'v1.2.3', 'assets', 'pending', blocked, api))
assert api.writes == 0


class ReleaseAPI:
    def __init__(self):
        self.tag = None
        self.release = None
        self.remote = {}
        self.content = {}
        self.uploads = []
        self.publishes = 0

    def __call__(self, endpoint, method='GET', payload=None):
        if '/git/ref/tags/' in endpoint:
            if self.tag is None:
                raise assets.journal.GitHubError(404, 'missing tag')
            return {'ref': 'refs/tags/v1.2.3', 'object': {'type': 'commit', 'sha': self.tag}}
        if endpoint.endswith('/git/refs'):
            assert method == 'POST'
            assert self.tag is None
            self.tag = payload['sha']
            return {}
        if '/releases?per_page=' in endpoint:
            return [deepcopy(self.release)] if self.release else []
        if '/releases/tags/' in endpoint:
            if self.release is None or self.release['draft']:
                raise assets.journal.GitHubError(404, 'missing release')
            return deepcopy(self.release)
        if endpoint.endswith('/releases'):
            assert method == 'POST'
            self.release = {'id': 5, **payload}
            return deepcopy(self.release)
        if '/releases/5/assets?' in endpoint:
            return list(self.remote.values())
        if endpoint.endswith('/releases/5'):
            if method == 'GET':
                return deepcopy(self.release)
            assert method == 'PATCH' and payload == {'draft': False}
            self.release['draft'] = False
            self.publishes += 1
            return deepcopy(self.release)
        raise AssertionError(endpoint)

    def download(self, repository, asset):
        return hashlib.sha256(self.content[asset['name']]).hexdigest()

    def upload(self, repository, tag, path):
        assert path.name not in self.remote
        self.uploads.append(path.name)
        self.content[path.name] = path.read_bytes()
        self.remote[path.name] = {'id': len(self.remote) + 1, 'name': path.name,
                                  'size': path.stat().st_size, 'state': 'uploaded'}


with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    for name, content in [('iso.part01', b'first immutable bytes'), ('SHA256SUMS', b'checksums'),
                          ('release-notes.md', b'Curated immutable release notes.\n')]:
        (directory / name).write_bytes(content)
    product = {'schema': 1, 'repository': 'owner/repo', 'revision': SHA,
               'assets': {p.name: assets.sha256(p) for p in directory.iterdir()}}
    api = ReleaseAPI()
    def reconcile(publish=False, auth=authorize):
        return assets.reconcile('owner/repo', product, directory, 'v1.2.3', SHA, publish, auth,
                                api, api.download, api.upload)
    staged = reconcile()
    assert staged['status'] == 'staged' and api.tag == SHA and len(api.uploads) == 3
    assert api.release['body'] == (directory / 'release-notes.md').read_text()
    uploads = len(api.uploads)
    assert reconcile(True)['status'] == 'published' and api.publishes == 1
    assert reconcile(True)['status'] == 'published' and len(api.uploads) == uploads and api.publishes == 1
    api.content['SHA256SUMS'] = b'tampered hosted bytes'
    reject(reconcile)
    api.content['SHA256SUMS'] = (directory / 'SHA256SUMS').read_bytes()
    api.tag = OTHER
    reject(reconcile)
    api.tag = SHA
    api.release['target_commitish'] = OTHER
    reject(reconcile)
    api.release['target_commitish'] = SHA
    api.release['body'] = 'unapproved release notes'
    reject(reconcile)
    api.release['body'] = (directory / 'release-notes.md').read_text()
    api.remote['unexpected'] = {'id': 99, 'name': 'unexpected', 'size': 1, 'state': 'uploaded'}
    reject(reconcile)
    # Recover an interrupted draft with one exact already-hosted asset.
    api = ReleaseAPI()
    api.tag = SHA
    api.release = {'id': 5, 'tag_name': 'v1.2.3', 'target_commitish': SHA, 'draft': True,
                   'body': (directory / 'release-notes.md').read_text()}
    api.upload('owner/repo', 'v1.2.3', directory / 'SHA256SUMS')
    api.uploads.clear()
    assert reconcile(True)['status'] == 'published' and api.uploads == ['iso.part01', 'release-notes.md']
    api = ReleaseAPI()
    reject(lambda: reconcile(True, blocked))
    assert api.tag is None and api.release is None
    (directory / 'iso.part01').write_bytes(b'changed local bytes')
    reject(reconcile)
    assert api.tag is None
# Adversarial release API responses; no external calls.
for response in ({}, {'id': True, 'tag_name': 'v1.2.3'}, {'id': 5, 'tag_name': 'v9.9.9'}):
    reject(lambda response=response: assets.validated_release(response, 'v1.2.3'))
reject(lambda: assets.release_for('owner/repo', 'v1.2.3', lambda endpoint: {}))
reject(lambda: assets.release_for('owner/repo', 'v1.2.3', lambda endpoint:
       [{'id': 5, 'tag_name': 'v1.2.3'}, {'id': 6, 'tag_name': 'v1.2.3'}]))
reject(lambda: assets.release_for('owner/repo', 'v1.2.3', lambda endpoint:
       [{'id': 9, 'tag_name': 'v9.9.9'}] * 100))
reject(lambda: assets.release_for('owner/repo', 'v1.2.3', lambda endpoint:
       {'id': 6, 'tag_name': 'v1.2.3'}, 5))

print('Publication CAS, immutable assets, partial recovery and live authority fixtures passed.')
