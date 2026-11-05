#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check a same-attempt result from the unchanged, byte-verifying boot producer."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from bindings import digest, require
from transfer import bindings, producer, validate, file_digest


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate local boot result field')
        result[key] = value
    return result


def main():
    require(os.environ['QUALIFICATION_MODE'] == 'refresh-evidence', 'Local boot handoff requires retained media')
    expected = os.environ['LOCAL_BOOT_RESULT_SHA256']
    require(re.fullmatch(r'[0-9a-f]{64}', expected or ''), 'Missing exact local boot result digest')
    with os.fdopen(os.open('boot-result.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Regular local boot result required')
        raw = stream.read(65537)
    require(0 < len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == expected, 'Changed or oversized local boot result')
    value = json.loads(raw, object_pairs_hook=unique)
    graph = json.loads(Path('ci-graph/candidate.json').read_text())
    bindings(graph, Path('ci-graph/plan.json'), os.environ['GRAPH_PLAN_SHA256'])
    inventory_path = Path('inventory-binding/manifest.json')
    require(file_digest(inventory_path) == os.environ['INVENTORY_MANIFEST_SHA256'], 'Changed local inventory binding')
    inventory = validate(json.loads(inventory_path.read_text()), 'inventory', graph['transport']['inventory'], digest(graph))
    require(set(value) == {'schemaVersion', 'disposition', 'producer', 'origin', 'graphSha256',
                          'mediaInput', 'verifierSha256', 'isoSha256', 'bootLogSha256'}
            and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and value['disposition'] == 'verified-retained' and value['bootLogSha256'] is None
            and value['producer'] == producer() and value['graphSha256'] == digest(graph)
            and value['mediaInput'] == os.environ['EXPECTED_MEDIA_INPUT']
            and value['verifierSha256'] == graph['policy']['boot']
            and re.fullmatch(r'[0-9a-f]{64}', value['isoSha256'])
            and value['isoSha256'] == inventory['isoSha256'], 'Local boot handoff differs from current evidence')
    origin = value['origin']
    require(isinstance(origin, dict) and set(origin) == {'revision', 'runId'}
            and re.fullmatch(r'[0-9a-f]{40}', origin.get('revision', ''))
            and type(origin.get('runId')) is int and origin['runId'] > 0, 'Missing original executed-boot identity')
    # Do not regenerate or relabel the result. Its exact bytes came from the
    # successful qualification job's original verifier and real ISO hashing.
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('manifest_sha256=' + expected + '\n')


if __name__ == '__main__':
    try:
        main()
    except (KeyError, ValueError, TypeError, OSError):
        print('Local retained-boot handoff validation failed', file=sys.stderr)
        sys.exit(1)
