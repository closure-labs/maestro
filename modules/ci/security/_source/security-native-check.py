#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check same-run native producer health without importing any candidate NARs."""
import datetime as dt
import os
from pathlib import Path
import sys

sys.path.insert(0, os.environ.get('MAESTRO_DECISION_CORE', str((Path(__file__).parent / '../../authority/_source/decisions'))))
import common
from security_decisions import normalize_findings


def check(native, cfg):
    now = dt.datetime.now(dt.timezone.utc)
    common.require(native.get('status') == 'complete' and native.get('scannerHealth') == 'healthy', 'Incomplete native qualification')
    scanned = common.timestamp(native.get('scannedAt'))
    common.require(scanned <= now and now - scanned <= dt.timedelta(hours=cfg.get('maxEvidenceAgeHours', 24)), 'Stale native qualification')
    database = native.get('database', {})
    common.require(database.get('valid') is True, 'Invalid native database')
    built = common.timestamp(database.get('built'))
    common.require(built <= scanned and now - built <= dt.timedelta(hours=cfg.get('maxDatabaseAgeHours', 48)), 'Stale native database')
    common.require('securityContext' in native, 'Native runtime policy coverage required')
    normalize_findings(native, 'maestro')
    return {'schema': 1, 'status': 'healthy-native-qualification', 'scannedAt': native['scannedAt']}


def main():
    root = Path(os.environ.get('MAESTRO_SYSTEM_ROOT', '.'))
    cfg = common.config(root / 'modules/ci/authority/_source/decision-policy.json')
    directory = Path(os.environ.get('SECURITY_OUTPUT', 'security-report'))
    native = common.load_json(directory / 'security-result.json')
    result = check(native, cfg)
    if os.environ.get('GITHUB_REF') == 'refs/heads/main':
        scans = common.load_json(directory / 'scans.json')
        product = common.load_json(directory / 'product.json')
        common.require(scans.get('profiles', {}).get('maestro') == native,
                       'Candidate observations differ from this run native report')
        common.require(scans.get('revision') == os.environ['GITHUB_SHA']
                       and product.get('revision') == scans['revision']
                       and scans.get('producer', {}).get('runId') == int(os.environ['GITHUB_RUN_ID'])
                       and scans['producer'].get('runAttempt') == int(os.environ['GITHUB_RUN_ATTEMPT']),
                       'Candidate report differs from current protected producer')
    common.emit(result)


if __name__ == '__main__':
    sys.exit(common.run(main))
