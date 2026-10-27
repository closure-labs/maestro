#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record a completed QEMU boot or explicitly authenticated retained boot evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from bindings import digest, require
from transfer import bindings, producer, validate, file_digest


def main():
    graph = json.loads(Path('ci-graph/candidate.json').read_text())
    bindings(graph, Path('ci-graph/plan.json'), os.environ.get('GRAPH_PLAN_SHA256'))
    mode = os.environ['QUALIFICATION_MODE']
    inventory_file = Path('inventory-binding/manifest.json')
    require(file_digest(inventory_file) == os.environ['INVENTORY_MANIFEST_SHA256'], 'Inventory manifest digest mismatch')
    inventory = validate(json.loads(inventory_file.read_text()), 'inventory', graph['transport']['inventory'], digest(graph))
    command_policy = hashlib.sha256(Path(os.environ['MAESTRO_BOOT_VERIFIER']).read_bytes()).hexdigest()
    require(graph['policy']['bootCommand'] == command_policy, 'Changed boot execution policy')
    policy = os.environ['MAESTRO_BOOT_POLICY_SHA256']
    require(graph['policy']['boot'] == policy, 'Changed boot evidence verifier')
    if mode in ('qualify-media', 'qualify-media-reuse-evidence'):
        disposition = 'executed'
        iso = Path('result-installer/iso/maestro-installer.iso')
        log = Path(os.environ['BOOT_LOG'])
        require(re.search(r'maestro-installer login:|Reached target .*Multi-User System|Started OpenSSH', log.read_text(), re.I), 'Missing successful QEMU boot log')
        origin = producer()
    elif mode in ('reuse', 'refresh-evidence'):
        disposition = 'verified-retained'
        state = json.loads(Path('reused-media/maestro-qualification-state.json').read_text())
        require(state['media_input'] == os.environ['EXPECTED_MEDIA_INPUT'], 'Changed retained boot inputs or verifier policy')
        subprocess.run(['maestro-ci-verify-inventory', 'reused-media', state['artifact_source_commit']], check=True)
        iso = Path('reused-media/result-installer/iso/maestro-installer.iso')
        origin = {'revision': state['artifact_source_commit'], 'runId': state['media_run_id']}
        log = None
    else:
        raise ValueError('Unknown boot evidence mode')
    with iso.open('rb') as stream:
        iso_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if mode != 'reuse':
        require(inventory['isoSha256'] == iso_digest, 'Booted ISO differs from bound inventory producer bytes')
    result = dict(schemaVersion=1, disposition=disposition, producer=producer(), origin=origin,
                  graphSha256=digest(graph), mediaInput=os.environ['EXPECTED_MEDIA_INPUT'],
                  verifierSha256=policy, isoSha256=iso_digest,
                  bootLogSha256=hashlib.sha256(log.read_bytes()).hexdigest() if log else None)
    path = Path('boot-result.json')
    path.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('manifest_sha256=' + hashlib.sha256(path.read_bytes()).hexdigest() + '\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write(f'Installer boot evidence: **{disposition}**. ISO SHA-256: `{iso_digest}`.\n')


if __name__ == '__main__':
    main()
