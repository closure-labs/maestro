# SPDX-License-Identifier: Apache-2.0
"""Freeze data before public inspection. Snapshots and observations grant no authority."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import destinations
import cache_publication
import publication_receipts
import scheduling

# Match the existing authenticated scans.json metadata byte bound.
LIMIT = 128 * 1024**2


def document(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate publication input field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite publication input')))


def read(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Publication input must be a regular file')
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('Publication input exceeds byte bound')
    return raw


def validate(product, scans):
    if (not isinstance(product, dict) or not isinstance(scans, dict)
            or type(product.get('schema')) is not int or product['schema'] != 1
            or type(scans.get('schema')) is not int or scans['schema'] != 1
            or product.get('repository') != 'closure-labs/maestro'
            or scans.get('repository') != product['repository']
            or not isinstance(product.get('revision'), str) or not re.fullmatch(r'[a-f0-9]{40}', product['revision'])
            or scans.get('revision') != product['revision']
            or not isinstance(product.get('products'), dict) or not product['products']
            or not isinstance(product.get('roots', {}), dict)
            or not isinstance(product.get('assets'), dict)
            or not isinstance(scans.get('profiles'), dict) or not set(product['products']) <= set(scans['profiles'])):
        raise ValueError('Malformed publication input structure')
    for entry in [*product['products'].values(), *product.get('roots', {}).values()]:
        if not isinstance(entry, dict) or not destinations.STORE.fullmatch(entry.get('storePath', '')):
            raise ValueError('Malformed publication root')
        destinations.nar_hash(entry.get('narHash', ''))


def readiness(product, scans, policy):
    """Reject locally unusable health metadata; passing grants no authority.

    Deliberately no network, signature/admission cache, receipt or success token.
    Signed provenance and current human authority are still checked afterward.
    """
    product = document(read(product))
    scans = document(read(scans))
    policy = document(read(policy))
    validate(product, scans)
    if (not isinstance(policy, dict) or policy.get('enabled') is not True
            or policy.get('repository') != product['repository']
            or not isinstance(policy.get('profiles'), list) or not policy['profiles']
            or any(not isinstance(profile, dict) or not isinstance(profile.get('database'), dict)
                   for profile in scans['profiles'].values())):
        raise ValueError('Malformed local native health metadata')
    deadline = scheduling.observation_expiry(scans, policy)
    if dt.datetime.now(dt.timezone.utc) >= deadline:
        raise ValueError('Local native observations expired before public inspection')
    return {'schema': 1, 'status': 'not-rejected-by-local-health', 'authorityClaim': False}


def freeze(product, scans, directory, policy):
    raw = {'product': read(product), 'scans': read(scans), 'policy': read(policy)}
    validate(*(document(raw[name]) for name in ('product', 'scans')))
    document(raw['policy'])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = {}
    for name, path in (('product', product), ('scans', scans), ('policy', policy)):
        (directory / (name + '.json')).write_bytes(raw[name])
        (directory / (name + '.json')).chmod(0o400)
        files[name] = {'path': str(path.absolute()), 'sha256': hashlib.sha256(raw[name]).hexdigest()}
    metadata = {'schema': 1, 'frozenAt': time.time(), 'files': files}
    encoded = json.dumps(metadata, sort_keys=True, allow_nan=False).encode()
    (directory / 'inputs.json').write_bytes(encoded)
    (directory / 'inputs.json').chmod(0o400)
    return hashlib.sha256(encoded).hexdigest()


def unchanged(directory, digest):
    raw = read(directory / 'inputs.json')
    if not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest) or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Publication snapshot metadata changed')
    metadata = document(raw)
    for name in ('product', 'scans', 'policy'):
        record = metadata['files'][name]
        if any(hashlib.sha256(read(path)).hexdigest() != record['sha256'] for path in
               (record['path'], directory / (name + '.json'))):
            raise ValueError('Publication inputs changed during public inspection or admission')
    return metadata


def fresh(directory, digest):
    metadata = unchanged(directory, digest)
    scans = document(read(directory / 'scans.json'))
    policy = document(read(directory / 'policy.json'))
    if dt.datetime.now(dt.timezone.utc) >= scheduling.observation_expiry(scans, policy):
        raise ValueError('Frozen native observations expired during admission')
    return metadata


def complete(directory, observation, output, digest, observation_digest):
    metadata = fresh(directory, digest)
    raw = read(observation)
    if hashlib.sha256(raw).hexdigest() != observation_digest:
        raise ValueError('Buffered public observation changed')
    observed_at = observation.stat().st_mtime
    if not metadata['frozenAt'] <= observed_at <= time.time():
        raise ValueError('Buffered public observation is outside this execution')
    product = json.loads(read(directory / 'product.json'))
    value = document(raw)
    expected = {path: destinations.nar_hash(digest) for path, digest in cache_publication.identities(product).items()}
    if (value.get('destination') != 'cache' or value.get('authorityClaim') is not False
            or value.get('expected') != expected or value.get('missing') != []):
        raise ValueError('Buffered public observation differs from frozen product')
    receipt = destinations.receipt(value, product)
    receipt['verifiedAt'] = dt.datetime.fromtimestamp(observed_at, dt.timezone.utc).isoformat()
    publication_receipts.validate(receipt, hashlib.sha256(destinations.canonical(product)).hexdigest(), 'cache')
    # No authorization is persisted. The caller must have just run the full
    # native gate; journal completion independently repeats live authority.
    fresh(directory, digest)
    output.write_bytes(destinations.canonical(receipt) + b'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('readiness', 'freeze', 'unchanged', 'fresh', 'complete'))
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--product', type=Path)
    parser.add_argument('--scans', type=Path)
    parser.add_argument('--policy', type=Path)
    parser.add_argument('--snapshot-digest')
    parser.add_argument('--observation-digest')
    parser.add_argument('--observation', type=Path)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    if args.operation != 'readiness' and args.directory is None:
        parser.error('--directory is required for frozen input checks')
    if args.operation == 'readiness':
        if args.product is None or args.scans is None or args.policy is None:
            parser.error('--product, --scans and --policy are required for readiness')
        print(json.dumps(readiness(args.product, args.scans, args.policy), sort_keys=True))
    elif args.operation == 'freeze':
        if args.policy is None:
            parser.error('--policy is required for freeze')
        print(freeze(args.product, args.scans, args.directory, args.policy))
    elif args.snapshot_digest is None:
        parser.error('--snapshot-digest is required for frozen input checks')
    elif args.operation == 'unchanged':
        unchanged(args.directory, args.snapshot_digest)
    elif args.operation == 'fresh':
        fresh(args.directory, args.snapshot_digest)
    else:
        if args.observation_digest is None:
            parser.error('--observation-digest is required for completion')
        complete(args.directory, args.observation, args.receipt, args.snapshot_digest, args.observation_digest)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        if os.environ.get('MAESTRO_CI_DIAGNOSTICS') == 'true':
            import diagnostics
            operation = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] in ('readiness', 'freeze', 'unchanged', 'fresh', 'complete') else 'unknown'
            reasons = {'Local native observations expired before public inspection': 'native-health-not-ready',
                       'Publication snapshot metadata changed': 'snapshot-metadata-changed',
                       'Publication inputs changed during public inspection or admission': 'frozen-inputs-changed',
                       'Frozen native observations expired during admission': 'native-observations-expired',
                       'Buffered public observation changed': 'observation-changed',
                       'Buffered public observation is outside this execution': 'observation-outside-execution'}
            result = {'schema': 1, 'status': 'blocked', 'operation': operation,
                      'errorType': type(error).__name__, 'reason': reasons.get(str(error), 'input-or-observation-invalid')}
            print(diagnostics.record(result, 'publication'), end='', file=sys.stderr)
        else:
            print('Publication preflight input or observation validation failed', file=sys.stderr)
        sys.exit(2)
