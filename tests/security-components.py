#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep root and split output findings bound to exact shipped files."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('normalizer', Path(__file__).parents[1] / 'nix/automation/security-normalize.py')
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)


def reject(call, message):
    try:
        call()
    except ValueError as error:
        assert message in str(error), str(error)
        return
    raise AssertionError('ambiguous or incomplete package identity accepted')


def component(ref, letter, output):
    root = '/nix/store/' + letter * 32 + '-openssl-1.0.1'
    return {'type': 'library', 'bom-ref': ref, 'name': 'openssl', 'version': '1.0.1',
            'purl': 'pkg:nix/openssl@1.0.1', 'properties': [
                {'name': 'nix:output_path', 'value': root},
                {'name': 'maestro:outputName', 'value': output}]}


root, binary = component('openssl:out', 'a', 'out'), component('openssl:bin', 'b', 'bin')
sbom = {'metadata': {'component': root}, 'components': [binary], 'dependencies': [], 'properties': [
    {'name': 'maestro:inventoryVersion', 'value': '2'},
    {'name': 'maestro:runtimeContext', 'value': '{}'},
    {'name': 'maestro:runtimeContextDigest', 'value': normalizer.digest({})},
    {'name': 'maestro:inventoryRoots', 'value': json.dumps([{
        'storePath': root['properties'][0]['value'], 'narHash': 'sha256-' + 'A' * 43 + '='}])}]}
report = {'matches': [{'artifact': {'id': item['bom-ref'], 'name': item['name'],
                                  'version': item['version'], 'purl': item['purl']},
                       'vulnerability': {'id': 'CVE-fixture', 'namespace': 'fixture', 'severity': 'High'},
                       'matchDetails': [{'type': 'exact-direct-match'}]} for item in (root, binary)]}
with patch.object(normalizer, 'component_locations', side_effect=lambda item: [item['properties'][0]['value'] + '/bin/openssl']):
    values = normalizer.observations(report, sbom)
assert {value['evidence']['binding']['component_ref'] for value in values} == {'openssl:out', 'openssl:bin'}
assert {value['exposureBindings'][0]['outputName'] for value in values} == {'out', 'bin'}
assert len({value['locations'][0] for value in values}) == 2

ambiguous = deepcopy(report)
ambiguous['matches'][0]['artifact']['id'] = 'unbound-scanner-id'
reject(lambda: normalizer.normalize(ambiguous, sbom, {}), 'ambiguous or absent')
duplicate = deepcopy(sbom)
duplicate['components'].append(deepcopy(root))
reject(lambda: normalizer.normalize(report, duplicate, {}), 'duplicate inventory identity')

now = datetime.now(timezone.utc).isoformat()
database, audit = {'valid': True, 'built': now}, {'vulnerabilities': {'list': []}}
incomplete = deepcopy(sbom)
incomplete['metadata']['component']['properties'].pop()
with patch.object(normalizer.Path, 'exists', return_value=True), \
        patch.object(normalizer, 'security_context', return_value={'schema': 1}):
    reject(lambda: normalizer.security_result({'matches': []}, incomplete, audit, database, now, {}),
           'exact output coverage')
    assert normalizer.security_result({'matches': []}, sbom, audit, database, now, {})['status'] == 'complete'
print('Root package and multiple output scanner identity fixtures passed.')
