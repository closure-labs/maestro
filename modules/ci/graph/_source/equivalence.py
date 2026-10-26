#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hosted derivation mutation checks; uses complete graph evaluation for each case."""
import json
from pathlib import Path
import subprocess
import sys
import time

root, output = map(Path, sys.argv[1:3])
original = json.loads((output / 'original.graph.json').read_text())
results = []
cases = [
    ('documentation', 'README.md', False, False, None),
    ('cli', 'modules/features/operator/cli/_source/maestroctl.sh', True, True, 'packages-x86_64-linux-maestroctl'),
    ('xo-storage', 'modules/features/xo/_source/storage-helper.sh', True, True, None),
    ('installer', 'modules/features/installer/_source/install-maestro.sh', False, True, 'packages-x86_64-linux-installer-iso'),
    ('packer', 'modules/features/xcp-ng/template/_source/build.sh', False, False, 'packages-x86_64-linux-deploy-template'),
    ('scan-policy', 'modules/ci/security/_source/security-policy.json', False, False, None),
]
appliance, iso = 'nixosConfigurations-maestro-config-system-build-toplevel', 'packages-x86_64-linux-installer-iso'
for name, path, expect_appliance, expect_iso, changed_target in cases:
    started = time.monotonic()
    source = root / path
    before = source.read_bytes()
    try:
        source.write_bytes(before + (b'\n ' if source.suffix == '.json' else b'\n# Maestro derivation mutation fixture\n'))
        value = subprocess.check_output(['nix', 'eval', '--accept-flake-config', '--no-write-lock-file', '--json',
                                         f'path:{root}#lib.ciGraph.x86_64-linux'], timeout=900)
        graph = json.loads(value)
        (output / f'{name}.graph.json').write_bytes(value)
        changed = sorted(key for key, target in graph['targets'].items()
                         if target['derivation'] != original['targets'][key]['derivation'])
        if (appliance in changed, iso in changed) != (expect_appliance, expect_iso):
            raise ValueError(f'{name}: unexpected appliance/ISO propagation: {changed}')
        if changed_target and changed_target not in changed:
            raise ValueError(f'{name}: owning output did not change')
        if name == 'scan-policy' and graph['policy']['scan'] == original['policy']['scan']:
            raise ValueError('Changed scan policy has no identity')
        results.append(dict(case=name, status='passed', changedDerivations=changed,
                            elapsedSeconds=round(time.monotonic()-started, 3)))
    finally:
        source.write_bytes(before)
    (output / 'results.json').write_text(json.dumps(dict(schemaVersion=1, candidateRevision=sys.argv[3],
        baseRevision=sys.argv[4], gatingEnabled=False, results=results), sort_keys=True, indent=2)+'\n')
