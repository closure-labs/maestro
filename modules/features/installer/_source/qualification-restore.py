#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Restore attested candidate bytes for qualification, independently of human admission."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys

sys.path.insert(0, os.environ.get('MAESTRO_DECISION_CORE', str((Path(__file__).parent / '../../../ci/authority/_source/decisions'))))
import common


def expected_paths(root, include_installer=True):
    flake_ref = f'path:{root}'
    if os.environ.get('GITHUB_ACTIONS') == 'true' and (root / '.git').exists():
        revision = os.environ['GITHUB_SHA']
        common.require(common.command(['git', '-C', str(root), 'rev-parse', 'HEAD']).strip() == revision,
                       'Qualification checkout differs from immutable candidate')
        flake_ref = f'git+file:{root}?shallow=1&rev={revision}' 
    values = [common.command(['nix', 'eval', '--accept-flake-config', '--raw',
                             f'{flake_ref}#nixosConfigurations.maestro.config.system.build.toplevel.outPath']).strip()]
    plan = common.load_json(root / 'modules/ci/graph/_lib/plans.json')['publish']['targets']
    for target in plan:
        values.append(common.command(['nix', 'eval', '--accept-flake-config', '--raw',
                                      f'{flake_ref}#{target["attribute"]}.outPath']).strip())
    if include_installer:
        import json
        manifest = json.loads(common.command(['nix', 'eval', '--accept-flake-config', '--json',
                                              f'{flake_ref}#lib.ciInstallerQualification.x86_64-linux']))
        values.extend(manifest['roots'].values())
    return set(values)


def restore(cfg, evidence, inventory, paths, transfer, source_sha=None, legacy_paths=None):
    # These checks authenticate protected-main producer provenance and native
    # technical health, not risk acceptance. Expired observations can restore
    # their original bytes so a fresh native scan can be produced.
    evidence, inventory = Path(evidence), Path(inventory)
    scans = common.scans(evidence / 'scans.json', cfg, allow_expired=True)
    product = common.product(evidence / 'product.json', cfg, scans)
    if source_sha is not None:
        common.require(product['revision'] == source_sha, 'Qualification source differs from exact candidate')
    identities = {value['storePath']: {'storePath': value['storePath'], 'narHash': value['narHash']}
                  for value in [*product['products'].values(), *product.get('roots', {}).values()]}
    current = set(identities) == set(paths)
    historical = legacy_paths is not None and set(identities) == set(legacy_paths)
    common.require(current or historical, 'Candidate roots differ from current evaluated qualification outputs')
    sbom = inventory / 'maestro-system.cdx.json'
    common.require(sbom.is_file() and not sbom.is_symlink(), 'Regular native inventory required')
    with sbom.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    native = scans['profiles']['maestro']
    common.require(native['evidence']['inventory']['sha256'] == actual,
                   'Qualification inventory differs from authenticated native producer bytes')
    properties = {p['name']: p['value'] for p in common.load_json(sbom)['properties']}
    import json
    subjects = json.loads(properties['maestro:inventoryRoots'])
    bound = {value['storePath']: value for value in subjects}
    common.require(len(bound) == len(subjects) and bound == identities,
                   'Native inventory roots differ from authenticated product')
    if all(Path(path).exists() for path in identities):
        transfer.verify_roots(list(identities.values()))
    else:
        transfer.restore(evidence, scans['transport'], list(identities.values()))
    return {'schema': 1, 'status': 'restored-for-native-qualification',
            'revision': product['revision'], 'roots': sorted(identities),
            'coverage': 'current' if current else 'historical-only'}


def main():
    root = Path(os.environ.get('MAESTRO_SYSTEM_ROOT', '.')).resolve()
    cfg = common.config(root / 'modules/ci/authority/_source/decision-policy.json')
    spec = importlib.util.spec_from_file_location('distribution_cache', os.environ['MAESTRO_DISTRIBUTION_CACHE_SOURCE'])
    transfer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transfer)
    result = restore(cfg, Path(os.environ.get('QUALIFICATION_EVIDENCE', 'qualified-distribution')),
                     Path(os.environ.get('SECURITY_INVENTORY', 'candidate')), expected_paths(root), transfer,
                     os.environ.get('QUALIFICATION_SOURCE_SHA'), expected_paths(root, include_installer=False))
    common.emit(result)


if __name__ == '__main__':
    sys.exit(common.run(main))
