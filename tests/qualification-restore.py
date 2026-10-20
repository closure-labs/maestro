#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Only authenticated exact native bytes may restore a qualification store."""
from copy import deepcopy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).parents[1] / 'nix/automation' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


restore = load('qualification-restore')
health = load('security-native-check')
ROOT = '/nix/store/' + 'a' * 32 + '-fixture'
REVISION = 'b' * 40
NAR = 'sha256-' + 'A' * 43 + '='
roots = [{'storePath': ROOT, 'narHash': NAR}]


def reject(call, message=None):
    try:
        call()
    except ValueError as error:
        if message:
            assert message in str(error), str(error)
        return
    raise AssertionError('unsafe qualification restore accepted')


with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    sbom = {'properties': [{'name': 'maestro:inventoryRoots', 'value': json.dumps(roots)}]}
    path = directory / 'maestro-system.cdx.json'
    path.write_text(json.dumps(sbom))
    native = {'evidence': {'inventory': {'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}}}
    scans = {'profiles': {'maestro': native}, 'transport': {'authenticated': 'manifest'}}
    product = {'revision': REVISION, 'products': {'maestro': roots[0]}, 'roots': {'same': {**roots[0], 'profile': 'maestro'}}}
    events = []
    transfer = SimpleNamespace(restore=Mock(side_effect=lambda *args: events.append('import')), verify_roots=Mock())
    with patch.object(restore.common, 'scans', side_effect=lambda *args, **kwargs: (events.append(('authenticated-scan', kwargs)) or scans)), \
            patch.object(restore.common, 'product', side_effect=lambda *args: (events.append('authenticated-product') or product)):
        # Policy disabled is deliberate: candidate preparation must precede risk
        # acceptance. Publication uses another leaf with the human gate intact.
        result = restore.restore({'enabled': False}, directory, directory, {ROOT}, transfer, REVISION)
        assert result['status'] == 'restored-for-native-qualification'
        assert events == [('authenticated-scan', {'allow_expired': True}), 'authenticated-product', 'import']
        transfer.restore.assert_called_once_with(directory, scans['transport'], roots)
        transfer.restore.reset_mock()
        reject(lambda: restore.restore({}, directory, directory, {ROOT + '-other'}, transfer), 'current evaluated')
        reject(lambda: restore.restore({}, directory, directory, {ROOT}, transfer, 'c' * 40), 'exact candidate')
        path.write_text(json.dumps({'properties': []}))
        reject(lambda: restore.restore({}, directory, directory, {ROOT}, transfer), 'authenticated native producer')
        transfer.restore.assert_not_called()
    with patch.object(restore.common, 'scans', side_effect=ValueError('bad attestation')):
        reject(lambda: restore.restore({}, directory, directory, {ROOT}, transfer), 'bad attestation')
        transfer.restore.assert_not_called()

now = dt.datetime.now(dt.timezone.utc)
context = {'schema': 1, 'tcpPorts': [], 'udpPorts': [], 'managementCIDRs': ['0.0.0.0/0'],
           'ssh': {}, 'execution': {'xoUser': 'xo', 'User': 'xo', 'Group': 'xo'},
           'capabilities': [], 'ambientCapabilities': [],
           'helpers': {'enableNFS': False, 'enableCIFS': False, 'enableVHD': False, 'fileRestore': False},
           'sudo': [], 'mountsDir': '/run/xo'}
native = {'status': 'complete', 'scannerHealth': 'healthy', 'observations': [], 'securityContext': context,
          'scannedAt': (now - dt.timedelta(minutes=1)).isoformat(),
          'database': {'valid': True, 'built': (now - dt.timedelta(hours=1)).isoformat()}}
assert health.check(native, {})['status'] == 'healthy-native-qualification'
stale = deepcopy(native)
stale['scannedAt'] = (now - dt.timedelta(days=2)).isoformat()
reject(lambda: health.check(stale, {}), 'Stale native qualification')
missing = deepcopy(native)
del missing['securityContext']
reject(lambda: health.check(missing, {}), 'runtime policy coverage')
print('Identity-only candidate restore, authentication order and fresh native health fixtures passed.')
