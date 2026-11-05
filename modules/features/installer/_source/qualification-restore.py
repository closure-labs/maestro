#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Restore attested candidate bytes for qualification, independently of human admission."""
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import sys
import subprocess

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


def cache_roots(paths):
    """Use configured trusted substituters only; never evaluate or build."""
    paths = sorted(paths)
    common.require(paths and all(isinstance(p, str) and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\s]+', p)
                   and not p.endswith('.drv') for p in paths), 'Only exact output paths may be substituted')
    command = ['nix-store', '--realise', '--option', 'max-jobs', '0', '--option', 'builders', '',
               '--option', 'fallback', 'false', '--option', 'require-sigs', 'true']
    config = os.environ.get('MAESTRO_QUALIFICATION_CACHE_CONFIG')
    if config:
        # Packaged from the same flake-file nixConfig accepted by ordinary
        # build commands. Do not duplicate a cache/key list in Python or CI.
        with open(config, 'rb') as stream:
            raw = stream.read(65537)
        common.require(len(raw) <= 65536, 'Oversized qualification cache configuration')
        cfg = json.loads(raw)
        common.require(isinstance(cfg, dict) and set(cfg) == {'substituters', 'keys'}
                       and all(isinstance(cfg[k], list) and cfg[k]
                               and all(isinstance(s, str) and s and not any(c.isspace() for c in s)
                                       for s in cfg[k]) for k in ('substituters', 'keys')),
                       'Invalid packaged qualification cache configuration')
        command += ['--option', 'extra-substituters', ' '.join(cfg['substituters']),
                    '--option', 'extra-trusted-public-keys', ' '.join(cfg['keys'])]
    try:
        # A miss should not first spend minutes downloading a partial closure.
        probe = common.operations.run([*command, '--dry-run', *paths], timeout=15,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if probe.returncode:
            return False
        fetched = common.operations.run([*command, *paths], timeout=120, stdout=subprocess.DEVNULL)
        return fetched.returncode == 0 and all(Path(p).exists() for p in paths)
    except (OSError, subprocess.SubprocessError):
        # Only this optional availability attempt falls back. Authenticated
        # evidence and final NAR checks are outside this handler and must fail.
        return False


def fetch_transport(evidence, scans, download=None):
    """Fetch the same exact producer transport lazily after cache availability."""
    if download is None:
        path = Path(os.environ.get('MAESTRO_DECISION_DOWNLOAD_SOURCE',
                                  str(Path(common.__file__).parent.parent / 'decision-download.py')))
        spec = importlib.util.spec_from_file_location('qualification_download', path)
        download = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(download)
    producer = scans['producer']
    common.require(type(producer.get('runId')) is int and producer['runId'] > 0
                   and type(producer.get('runAttempt')) is int and producer['runAttempt'] > 0,
                   'Typed exact qualification producer required')
    run = download.api(f"actions/runs/{producer['runId']}")
    common.require(download.trusted(run) and run.get('id') == producer['runId']
                   and run.get('run_attempt') == producer['runAttempt']
                   and run.get('head_sha') == scans['revision']
                   and run.get('path', '').split('@')[0] == producer.get('workflow') == '.github/workflows/ci.yml',
                   'Lazy transport producer changed')
    inventory = download.api(f"actions/runs/{producer['runId']}/artifacts?per_page=100")
    common.require(type(inventory.get('total_count')) is int
                   and inventory['total_count'] == len(inventory['artifacts']) <= 100,
                   'Incomplete lazy transport artifact inventory')
    download.distribution_transport(Path(evidence), scans, run, inventory)


def restore(cfg, evidence, inventory, paths, transfer, source_sha=None, legacy_paths=None,
            *, substitute=None, ensure_transport=None):
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
    origin = 'local-store'
    if all(Path(path).exists() for path in identities):
        transfer.verify_roots(list(identities.values()))
    elif substitute is not None and substitute(set(identities)):
        origin = 'configured-substituters'
        # A successful subprocess is never NAR authority. Mismatch must not
        # fall back and disappear into a fresh scan.
        transfer.verify_roots(list(identities.values()))
    else:
        origin = 'producer-artifact'
        if ensure_transport is not None:
            ensure_transport(evidence, scans)
        transfer.restore(evidence, scans['transport'], list(identities.values()))
    return {'schema': 1, 'status': 'restored-for-native-qualification',
            'revision': product['revision'], 'roots': sorted(identities),
            'transportSource': origin,
            'coverage': 'current' if current else 'historical-only'}


def main():
    root = Path(os.environ.get('MAESTRO_SYSTEM_ROOT', '.')).resolve()
    cfg = common.config(root / 'modules/ci/authority/_source/decision-policy.json')
    spec = importlib.util.spec_from_file_location('distribution_cache', os.environ['MAESTRO_DISTRIBUTION_CACHE_SOURCE'])
    transfer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transfer)
    result = restore(cfg, Path(os.environ.get('QUALIFICATION_EVIDENCE', 'qualified-distribution')),
                     Path(os.environ.get('SECURITY_INVENTORY', 'candidate')), expected_paths(root), transfer,
                     os.environ.get('QUALIFICATION_SOURCE_SHA'), expected_paths(root, include_installer=False),
                     substitute=cache_roots if os.environ.get('QUALIFICATION_CACHE_FIRST') == 'true' else None,
                     ensure_transport=fetch_transport if os.environ.get('QUALIFICATION_CACHE_FIRST') == 'true' else None)
    common.emit(result)


if __name__ == '__main__':
    sys.exit(common.run(main))
