#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Installer code coverage and privileges cannot disappear behind an ISO hash."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch, mock_open


BASE = Path(__file__).parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, BASE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inventory = load('inventory', 'modules/ci/authority/_source/security-inventory.py')
candidate = load('candidate', 'modules/ci/authority/_source/decision-candidate.py')
decisions = load('decisions', 'modules/ci/authority/_source/decisions/security_decisions.py')
normalizer = load('normalizer', 'modules/ci/authority/_source/security-normalize.py')


def reject(call, text=None):
    try:
        call()
    except ValueError as error:
        assert text is None or text in str(error), str(error)
        return error
    raise AssertionError('incomplete installer evidence accepted')


paths = ['/nix/store/' + value * 32 + '-' + name for value, name in
         [('a', 'appliance'), ('b', 'installer'), ('c', 'boot-origin'), ('d', 'installer-helper')]]
subjects = [{'storePath': path, 'narHash': 'sha256-' + 'A' * 43 + '='} for path in paths[:3]]
policy = {'ssh': {'PasswordAuthentication': False, 'AuthorizedKeysFile': '/run/maestro-bootstrap/authorized_keys'},
          'firewall': {'allowedTCPPorts': [], 'allowedUDPPorts': [], 'extraCommands': 'allow management CIDRs'},
          'sudo': {'enable': True, 'wheelNeedsPassword': False, 'extraRules': []},
          'operator': {'extraGroups': ['wheel'], 'passwordState': 'locked', 'rootPasswordState': 'empty', 'mutableUsers': True},
          'systemdInitrd': True, 'bootModes': {'bios': True, 'efi': True, 'memtest': True},
          'bootPolicy': {'kernelParams': ['console=hvc0'], 'emergencyMode': True, 'initrdEmergencyAccess': 'disabled'}}
manifest = {'schema': 1, 'iso': '/nix/store/' + 'e' * 32 + '-installer.iso', 'system': paths[1],
            'roots': {'installer-system': paths[1], 'installer-boot': paths[2]}, 'policy': policy,
            'bindings': [{'source': paths[2] + '/bin/boot', 'root': paths[2], 'destination': '/EFI/BOOT/BOOTX64.EFI'}]}


def component(path):
    return {'type': 'file', 'name': path.rsplit('-', 1)[1], 'bom-ref': path,
            'properties': [{'name': 'nix:output_path', 'value': path},
                           {'name': 'nix:drv_path', 'value': path + '.drv'}]}


sbom = {'components': [component(path) for path in paths], 'dependencies': []}
closure = {path: {'narHash': subjects[0]['narHash'], 'deriver': path + '.drv'} for path in paths}
with patch.object(inventory.subprocess, 'check_output', return_value=json.dumps(closure).encode()):
    inventory.bind_inventory_roots(deepcopy(sbom), subjects, manifest)
    reject(lambda: inventory.bind_inventory_roots(deepcopy(sbom), subjects[:1], manifest), 'installer qualification roots')
    incomplete = deepcopy(sbom)
    incomplete['components'].pop()  # Installer-only helper omitted despite healthy boot roots.
    reject(lambda: inventory.bind_inventory_roots(incomplete, subjects, manifest), 'omits publication closure')
    incomplete = deepcopy(sbom)
    incomplete['components'].pop(2)  # Exact BIOS/EFI/initrd native origin omitted.
    reject(lambda: inventory.bind_inventory_roots(incomplete, subjects, manifest), 'omits publication closure')

# Unattributed ELF/PE source blobs cannot be laundered into static data coverage.
static = deepcopy(sbom)
static['components'].pop(2)
for magic in (b'\x7fELF', b'MZxx'):
    static_closure = deepcopy(closure)
    static_closure[paths[2]]['deriver'] = ''
    with patch.object(inventory.subprocess, 'check_output', side_effect=lambda args, **kwargs:
                      '' if '--valid-derivers' in args else json.dumps(static_closure).encode()), \
            patch.object(inventory.Path, 'exists', return_value=True), \
            patch.object(inventory.Path, 'is_symlink', return_value=False), \
            patch.object(inventory.Path, 'is_file', return_value=True), \
            patch.object(inventory.Path, 'open', mock_open(read_data=magic)):
        error = reject(lambda: inventory.bind_inventory_roots(deepcopy(static), subjects, manifest), 'omits publication closure')
        assert 'native code lacks package provenance' in str(error.__cause__)

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    (root / 'modules/ci/graph/_lib').mkdir(parents=True)
    (root / 'modules/ci/graph/_lib/plans.json').write_text(json.dumps({'publish': {'targets': [{'name': 'system', 'attribute': 'fixture'}]}}))
    def evaluate(*args):
        return json.dumps(manifest) if '--json' in args else paths[0]
    native = {'status': 'complete', 'scannerHealth': 'healthy', 'scannedAt': datetime.now(timezone.utc).isoformat(),
              'subjects': subjects, 'coverage': {'contract': 'maestro-distribution-v2', 'manifest': manifest}}
    with patch.object(candidate, 'command', side_effect=evaluate):
        _, product = candidate.prepare(native, root, 'f' * 40, 1, 1, '.github/workflows/ci.yml')
        assert product['roots']['installer-boot']['storePath'] == paths[2]
        invalid = deepcopy(native)
        del invalid['coverage']
        reject(lambda: candidate.prepare(invalid, root, 'f' * 40, 1, 1, '.github/workflows/ci.yml'), 'coverage differs')
        invalid = deepcopy(native)
        invalid['subjects'].pop()
        reject(lambda: candidate.prepare(invalid, root, 'f' * 40, 1, 1, '.github/workflows/ci.yml'), 'root is missing')

context = {'schema': 2, 'tcpPorts': [443], 'udpPorts': [], 'managementCIDRs': ['10.0.0.0/8'],
           'ssh': {}, 'execution': {'xoUser': 'xo', 'User': 'xo', 'Group': 'xo'}, 'capabilities': [], 'ambientCapabilities': [],
           'helpers': {'enableNFS': False, 'enableCIFS': False, 'enableVHD': False, 'fileRestore': False},
           'sudo': [], 'mountsDir': '/run/xo', 'installer': policy}
decisions.validate_context(context)
native = {'status': 'complete', 'scannerHealth': 'healthy', 'securityContext': context, 'observations': [{
    'component': 'pkg:nix/openssl@3.5.9', 'advisory': 'CVE-2026-12345', 'severity': 'Low',
    'knownExploited': False, 'aliases': [], 'fixVersions': [], 'locations': ['/nix-output/out/bin/openssl'], 'locationCoverage': 'complete'}]}
baseline = decisions.normalize_findings(native, 'maestro')
rebuilt = deepcopy(native)
rebuilt['observations'][0]['component'] = 'pkg:nix/openssl@3.5.10'
assert decisions.evaluate(rebuilt, 'maestro', baseline)['status'] == 'covered'
for field, value in [('ssh', {'PasswordAuthentication': True}), ('operator', {**policy['operator'], 'passwordState': 'empty'})]:
    changed = deepcopy(native)
    changed['securityContext']['installer'][field] = value
    assert decisions.evaluate(changed, 'maestro', baseline)['status'] == 'review-required'
lost = deepcopy(native)
lost['securityContext'].pop('installer')
lost['securityContext']['schema'] = 1
reject(lambda: decisions.evaluate(lost, 'maestro', baseline), 'installer security context disappeared')

# Immutable media paths belong to evidence, not stable privilege identity.
runtime = {'allowedTCPPorts': [443], 'allowedUDPPorts': [], 'managementCIDRs': ['10.0.0.0/8'],
           'ssh': {}, 'xoUser': 'xo', 'User': 'xo', 'Group': 'xo',
           'CapabilityBoundingSet': [], 'AmbientCapabilities': [],
           'storage': {'enableNFS': False, 'enableCIFS': False, 'enableVHD': False, 'mountsDir': '/run/xo'},
           'fileRestore': {'enable': False}, 'sudo': []}
native_context = {'runtime': runtime, 'installerQualification': manifest}
def native_sbom(value):
    return {'components': [], 'properties': [
        {'name': 'maestro:runtimeContext', 'value': json.dumps(value)},
        {'name': 'maestro:runtimeContextDigest', 'value': normalizer.digest(value)},
        {'name': 'maestro:inventoryRoots', 'value': json.dumps(subjects)},
        {'name': 'maestro:qualificationCoverage', 'value': json.dumps({'contract': 'maestro-distribution-v2', 'manifest': value['installerQualification']})},
        {'name': 'maestro:inventoryVersion', 'value': '2'}]}
bound = native_sbom(native_context)
assert normalizer.security_context(bound) == context
updated_context = deepcopy(native_context)
updated_context['installerQualification']['iso'] = manifest['iso'].replace('e' * 32, 'f' * 32)
assert normalizer.security_context(native_sbom(updated_context)) == context
now = datetime.now(timezone.utc).isoformat()
result = normalizer.security_result({'matches': []}, bound, {'vulnerabilities': {'list': []}}, {'valid': True, 'built': now}, now, {})
assert result['coverage']['manifest'] == manifest
invalid = deepcopy(bound)
invalid['properties'][2]['value'] = json.dumps(subjects[:2])
reject(lambda: normalizer.security_result({'matches': []}, invalid, {'vulnerabilities': {'list': []}}, {'valid': True, 'built': now}, now, {}), 'coverage is incomplete')
print('Installer helper/boot coverage, exact candidate roots and stable privilege carryover fixtures passed.')
