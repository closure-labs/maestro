#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind complete job, boot, inventory and current native scan results to one plan."""
import hashlib
import json
import os
from pathlib import Path
import re

from graph import digest, require
from transfer import bindings, producer
from comparison import read_bound_reference


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_boot(boot, graph, route, expected_producer):
    require(boot.get('schemaVersion') == 1 and type(boot['schemaVersion']) is int
            and boot.get('producer') == expected_producer, 'Changed boot producer binding')
    require(boot.get('graphSha256') == digest(graph)
            and boot.get('mediaInput') == route['qualification']['media_input']
            and boot.get('verifierSha256') == graph['policy']['boot'], 'Changed boot input or verifier policy')
    mode = route['qualification']['mode']
    disposition = 'executed' if mode in ('qualify-media', 'qualify-media-reuse-evidence') else 'verified-retained'
    require(boot.get('disposition') == disposition, 'Unjustified boot skip or execution claim')
    require(isinstance(boot.get('isoSha256'), str) and len(boot['isoSha256']) == 64, 'Missing exact ISO digest')
    if disposition == 'executed':
        require(isinstance(boot.get('bootLogSha256'), str) and len(boot['bootLogSha256']) == 64, 'Missing completed boot log')


def inventory_iso_binding(boot, inventory_sha, expected_producer):
    # The boot job already verifies/hashes the exact executed or retained media.
    # Explicitly bind that digest to this inventory, without another ISO download
    # or mutating the earlier inventory artifact (reuse may have no local ISO).
    require(boot.get('producer') == expected_producer
            and re.fullmatch(r'[0-9a-f]{64}', boot.get('isoSha256', ''))
            and re.fullmatch(r'[0-9a-f]{64}', inventory_sha), 'Incomplete inventory ISO binding')
    return dict(schemaVersion=1, producer=expected_producer,
                inventorySha256=inventory_sha, isoSha256=boot['isoSha256'])


def main():
    graph = json.loads(Path('ci-graph/candidate.json').read_text())
    bindings(graph, Path('ci-graph/plan.json'), os.environ.get('GRAPH_PLAN_SHA256'))
    route = json.loads(os.environ['CI_PLAN'])
    plan = json.loads(Path('ci-graph/plan.json').read_text())
    require(plan['mode'] == graph['mode'] and plan['gatingEnabled'] == graph['gatingEnabled'], 'Changed scheduling mode')
    require(plan['decisions']['routePlanSha256'] == digest(route), 'Route differs from bound job decisions')
    boot = json.loads(Path('boot-result.json').read_text())
    require(file_digest('boot-result.json') == os.environ['BOOT_RESULT_SHA256'], 'Boot result digest mismatch')
    validate_boot(boot, graph, route, producer())
    require(os.environ['AUDIT_RESULT'] == 'success' and os.environ['SCAN_RESULT'] == 'success'
            and os.environ['QUALIFICATION_RESULT'] == 'success', 'Missing complete validation obligation')
    reference_path = Path('complete-audit/reference.json')
    reference, _ = read_bound_reference(reference_path.parent, graph, os.environ['GRAPH_PLAN_SHA256'],
                                       os.environ['AUDIT_REFERENCE_SHA256'])
    native = json.loads(Path('security-report/security-result.json').read_text())
    require(native.get('status') == 'complete' and native.get('scannerHealth') == 'healthy', 'Incomplete native scan')
    # Current database and effective runtime policy checks run through the existing
    # native verifier immediately before this binding is created.
    manifest = dict(schemaVersion=2, validationMode='complete-audit', producer=producer(), planSha256=os.environ['GRAPH_PLAN_SHA256'],
                    graphSha256=digest(graph), routePlanSha256=digest(route), boot=boot,
                    inventoryTransferSha256=os.environ['INVENTORY_TRANSFER_SHA256'],
                    inventoryIsoBinding=inventory_iso_binding(boot, os.environ['INVENTORY_TRANSFER_SHA256'], producer()),
                    nativeScanSha256=file_digest('security-report/security-result.json'),
                    auditReferenceSha256=file_digest(reference_path), completeAuditSha256=reference['auditSha256'],
                    jobs={key: os.environ[key] for key in ['AUDIT_RESULT', 'SCAN_RESULT', 'QUALIFICATION_RESULT']},
                    schedulingMode=plan['mode'], completeValidationRequired=True)
    output = Path('ci-result.json')
    output.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('manifest_sha256=' + file_digest(output) + '\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write(f"Bound release evidence to graph `{digest(graph)}`. Boot: **{boot['disposition']}**. Complete audit and fresh native scan passed.\n")


if __name__ == '__main__':
    main()
