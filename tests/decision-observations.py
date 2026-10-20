#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native evidence failures must never become covered human decisions."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'nix' / 'automation' / f'security-{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


normalizer = load('normalize')
inventory = load('inventory')
root = '/nix/store/' + 'a' * 32 + '-fixture-1'
context = {'schemaVersion': 2, 'runtime': {
    'allowedTCPPorts': [443], 'allowedUDPPorts': [], 'managementCIDRs': ['10.0.0.0/8'],
    'ssh': {'PasswordAuthentication': False, 'PermitRootLogin': 'no'}, 'xoUser': 'xo', 'User': 'xo', 'Group': 'xo',
    'CapabilityBoundingSet': ['CAP_NET_BIND_SERVICE'], 'AmbientCapabilities': ['CAP_NET_BIND_SERVICE'],
    'storage': {'enableNFS': True, 'enableCIFS': False, 'enableVHD': False, 'mountsDir': '/run/xo'},
    'fileRestore': {'enable': False}, 'sudo': [{'users': ['xo'], 'commands': [{'command': root + '/bin/helper', 'options': ['NOPASSWD']}]}]}}
component = {'name': 'fixture', 'version': '1', 'type': 'library', 'bom-ref': 'fixture', 'purl': 'pkg:nix/fixture@1',
             'properties': [{'name': 'nix:output_path', 'value': root}, {'name': 'maestro:outputName', 'value': 'lib'},
                            {'name': 'maestro:patches', 'value': '[]'}, {'name': 'maestro:source', 'value': '"immutable-source"'}]}
subjects = [{'storePath': root, 'narHash': 'sha256-' + 'A' * 43 + '='}]
sbom = {'bomFormat': 'CycloneDX', 'components': [component], 'dependencies': [], 'properties': [
    {'name': 'maestro:inventoryVersion', 'value': '2'}, {'name': 'maestro:runtimeContext', 'value': json.dumps(context)},
    {'name': 'maestro:runtimeContextDigest', 'value': normalizer.digest(context)},
    {'name': 'maestro:inventoryRoots', 'value': json.dumps(subjects)}]}
report = {'matches': [{'artifact': {'id': 'fixture', 'name': 'fixture', 'version': '1', 'purl': 'pkg:nix/fixture@1'},
                       'vulnerability': {'id': 'GHSA-aaaa-bbbb-cccc', 'namespace': 'github:language:npm', 'severity': 'Medium',
                                         'cvss': [{'metrics': {'baseScore': 5.5}}], 'fix': {'versions': ['2']}},
                       'relatedVulnerabilities': [{'id': 'CVE-2026-12345', 'severity': 'High', 'cvss': [{'metrics': {'baseScore': 8.5}}],
                                                   'knownExploited': [{'cve': 'CVE-2026-12345'}]}],
                       'matchDetails': [{'type': 'exact-direct-match'}]}]}


def reject(call):
    try:
        call()
    except (ValueError, KeyError):
        return
    raise AssertionError('incomplete or ambiguous evidence was accepted')


def fake_walk(path, **kwargs):
    return [(path, [], ['libfixture.so'])]


with patch.object(normalizer.Path, 'exists', return_value=True), patch.object(normalizer.Path, 'is_file', return_value=False), patch.object(normalizer.os, 'walk', side_effect=fake_walk):
    observed = normalizer.observations(report, sbom)[0]
    assert observed['aliases'] == ['CVE-2026-12345', 'GHSA-aaaa-bbbb-cccc']
    assert observed['admissionSeverity'] == 'High' and observed['cvss'] == 8.5 and observed['knownExploited'] is True
    assert observed['locations'] == [root + '/libfixture.so']
    assert observed['exposureBindings'] == [{'location': root + '/libfixture.so', 'outputName': 'lib', 'relativePath': 'libfixture.so'}]
    # Raw locations change; authenticated logical output exposure remains stable.
    changed = deepcopy(sbom)
    changed['components'][0]['properties'][0]['value'] = root.replace('a' * 32, 'b' * 32)
    next_observation = normalizer.observations(report, changed)[0]
    assert next_observation['locations'] != observed['locations']
    assert next_observation['exposureBindings'][0]['relativePath'] == 'libfixture.so'
    for change in ['purl', 'version', 'output']:
        invalid = deepcopy(sbom)
        if change == 'output':
            invalid['components'][0]['properties'] = invalid['components'][0]['properties'][:1]
        else:
            invalid['components'][0].pop(change)
        reject(lambda: normalizer.observations(report, invalid))
    malformed = deepcopy(report)
    malformed['matches'][0]['relatedVulnerabilities'][0]['cvss'][0]['metrics']['baseScore'] = float('nan')
    reject(lambda: normalizer.observations(malformed, sbom))
    now = datetime.now(timezone.utc)
    database = {'valid': True, 'built': now.isoformat()}
    completed = normalizer.security_result(report, sbom, {'vulnerabilities': {'list': []}}, database, now.isoformat(), {})
    assert completed['scannerHealth'] == 'healthy' and completed['subjects'] == subjects
    policy = completed['securityContext']
    rebuilt = deepcopy(sbom)
    newer_context = deepcopy(context)
    rebuilt_root = root.replace('a' * 32, 'b' * 32)
    newer_context['lockDigest'] = 'changed irrelevant lock digest'
    newer_context['runtime']['xoPackage'] = rebuilt_root
    newer_context['runtime']['sudo'][0]['commands'][0]['command'] = rebuilt_root + '/bin/helper'
    rebuilt['components'][0]['properties'][0]['value'] = rebuilt_root
    for prop in rebuilt['properties']:
        if prop['name'] == 'maestro:runtimeContext':
            prop['value'] = json.dumps(newer_context)
    assert normalizer.security_context(rebuilt) == policy
    reject(lambda: normalizer.security_result(report, sbom, {'vulnerabilities': {'list': []}}, {**database, 'built': (now - timedelta(hours=49)).isoformat()}, now.isoformat(), {}))
    reject(lambda: normalizer.security_result(report, sbom, {'vulnerabilities': {'list': []}}, {**database, 'valid': False}, now.isoformat(), {}))
    reject(lambda: normalizer.rust_observations({'vulnerabilities': {'list': [{'advisory': {'id': 'RUSTSEC-2026-0001'}, 'package': {'name': 'fixture', 'version': '1'}}]}}, sbom))

with patch.object(normalizer.Path, 'exists', return_value=False):
    reject(lambda: normalizer.component_locations(component))
    reject(lambda: normalizer.security_result({'matches': []}, sbom, {'vulnerabilities': {'list': []}},
                                              {'valid': True, 'built': datetime.now(timezone.utc).isoformat()},
                                              datetime.now(timezone.utc).isoformat(), {}))

# A valid scanner cannot compensate for an omitted publication output.
with patch.object(inventory.subprocess, 'check_output', return_value=json.dumps({root: {'narHash': subjects[0]['narHash']}, root + '-missing': {'narHash': subjects[0]['narHash']}}).encode()):
    reject(lambda: inventory.bind_inventory_roots(deepcopy(sbom), subjects))
with patch.object(inventory.subprocess, 'check_output', return_value=json.dumps({root: {'narHash': subjects[0]['narHash']}}).encode()):
    inventory.bind_inventory_roots(deepcopy(sbom), subjects)
spec = importlib.util.spec_from_file_location('candidate', Path(__file__).parents[1] / 'nix/automation/decision-candidate.py')
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
builder = {'id': 12, 'run_attempt': 2, 'head_sha': 'a' * 40, 'head_branch': 'main',
           'repository': {'full_name': 'closure-labs/maestro'}, 'path': '.github/workflows/release-continuation.yml'}
with patch.dict(os.environ, {'GITHUB_RUN_ID': '12', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_SHA': 'a' * 40,
                            'DECISION_PRODUCER_WORKFLOW': '.github/workflows/release.yml'}):
    with patch.object(candidate, 'command', return_value=json.dumps(builder)):
        identity = candidate.producer_identity()
        assert identity['workflow'].endswith('/release-continuation.yml')
        assert identity['signerWorkflow'].endswith('/release.yml')
        assert identity['revision'] == 'a' * 40 and identity['runAttempt'] == 2
    for alteration in ({'head_branch': 'feature'}, {'head_sha': 'b' * 40}, {'run_attempt': 1},
                       {'path': '.github/workflows/untrusted.yml'}, {'repository': {'full_name': 'attacker/maestro'}}):
        with patch.object(candidate, 'command', return_value=json.dumps({**builder, **alteration})):
            reject(candidate.producer_identity)
print('Complete observations, stable exposure, scanner health, closure coverage and reusable producer fixtures passed.')
