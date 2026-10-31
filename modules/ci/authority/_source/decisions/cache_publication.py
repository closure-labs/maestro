# SPDX-License-Identifier: Apache-2.0
"""Explicit cache scope within an independently complete signed distribution."""
import argparse
import json
import os
import stat
from pathlib import Path
import re

SCOPE = 'selected-project-closures'
STORE = re.compile(r'/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}')
NAR = re.compile(r'sha256-[A-Za-z0-9+/]{43}=')


def require(value, message):
    if not value:
        raise ValueError(message)


def contract(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'scope', 'roots'}
            and type(value['schema']) is int and value['schema'] == 1 and value['scope'] == SCOPE
            and isinstance(value['roots'], list) and 0 < len(value['roots']) <= 32
            and all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', name) for name in value['roots'])
            and len(set(value['roots'])) == len(value['roots']), 'Invalid explicit cache publication scope')
    return value


def identities(product, policy=None, required=False):
    selected = product.get('cachePublication')
    if selected is None:
        require(not required, 'Historical product lacks explicit cache scope; qualify a new signed product')
        # Historical signed contracts remain readable, without retroactively
        # narrowing a previous claim that all retained roots were distributed.
        entries = [*product['products'].values(), *product.get('roots', {}).values()]
    else:
        require(isinstance(selected, dict) and set(selected) == {'schema', 'scope', 'roots', 'closure'}, 'Incomplete signed cache scope')
        declared = {key: selected[key] for key in ('schema', 'scope', 'roots')}
        contract(declared)
        if policy is not None:
            require(declared == contract(policy.get('cachePublication')), 'Signed cache scope differs from checked publication policy')
        roots = product.get('roots', {})
        require(all(name in roots for name in selected['roots']), 'Selected cache root absent from complete product')
        entries = [roots[name] for name in selected['roots']]
    result = {}
    for entry in entries:
        require(isinstance(entry, dict) and isinstance(entry.get('storePath'), str)
                and STORE.fullmatch(entry['storePath']) and not entry['storePath'].endswith('.drv')
                and isinstance(entry.get('narHash'), str) and NAR.fullmatch(entry['narHash']), 'Invalid cache root identity')
        path, digest = entry['storePath'], entry['narHash']
        require(path not in result or result[path] == digest, 'Conflicting cache root identities')
        result[path] = digest
    require(result, 'Empty selected cache inventory')
    return result


def records(value, expected):
    if isinstance(value, list):
        require(all(isinstance(row, dict) and isinstance(row.get('path'), str) for row in value), 'Invalid cache closure records')
        require(len({row['path'] for row in value}) == len(value), 'Duplicate cache closure identities')
        value = {row['path']: row for row in value}
    require(isinstance(value, dict) and 0 < len(value) <= 10000, 'Invalid selected closure inventory')
    result = {}
    for path, row in value.items():
        require(isinstance(path, str) and STORE.fullmatch(path) and isinstance(row, dict)
                and isinstance(row.get('narHash'), str) and NAR.fullmatch(row['narHash'])
                and isinstance(row.get('references'), list)
                and all(isinstance(child, str) and STORE.fullmatch(child) for child in row['references'])
                and len(set(row['references'])) == len(row['references']), 'Invalid selected dependency identity')
        result[path] = {'narHash': row['narHash'], 'references': sorted(row['references'])}
    require(all(result.get(path, {}).get('narHash') == digest for path, digest in expected.items()),
            'Selected closure lacks exact signed cache roots')
    require(sum(len(row['references']) for row in result.values()) <= 100000, 'Selected cache closure exceeds edge bound')
    seen, frontier = set(), list(expected)
    while frontier:
        path = frontier.pop()
        require(path in result, 'Incomplete selected dependency closure')
        if path not in seen:
            seen.add(path)
            frontier.extend(result[path]['references'])
    require(seen == set(result), 'Unrelated paths in selected cache closure')
    return result


def attach(product, policy, query):
    selected = dict(contract(policy['cachePublication']))
    selected['closure'] = {}
    product['cachePublication'] = selected
    expected = identities(product, policy, required=True)
    selected['closure'] = records(query(sorted(expected)), expected)
    return selected


def closure(product):
    if 'cachePublication' not in product:
        return None
    return records(product['cachePublication']['closure'], identities(product, required=True))


def scoped_metadata(product, retained, query):
    """Validate the signed selected closure against actual and retained bytes.

    The caller has already run the full live gate and recursively verified the
    complete retained distribution. Public metadata never selects upload paths.
    """
    expected = identities(product, required=True)
    signed = closure(product)
    actual = records(query(sorted(expected)), expected)
    require(actual == signed, 'Actual selected closure differs from signed cache scope')
    require(isinstance(retained, dict), 'Retained closure inventory required')
    require(all(isinstance(retained.get(path), dict) and retained[path].get('narHash') == row['narHash']
                for path, row in actual.items()), 'Selected dependency absent or changed in authenticated retained closure')
    return {path: {'narHash': row['narHash']} for path, row in actual.items()}


def load(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'Regular cache contract document required')
        raw = source.read(128 * 1024**2 + 1)
    require(len(raw) <= 128 * 1024**2, 'Cache contract document exceeds byte bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate cache contract field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite cache contract')))


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('operation', choices=('check', 'scope'))
    cli.add_argument('--product', type=Path, required=True)
    cli.add_argument('--policy', type=Path, required=True)
    cli.add_argument('--retained', type=Path)
    cli.add_argument('--output', type=Path)
    args = cli.parse_args()
    product, policy = load(args.product), load(args.policy)
    identities(product, policy, required=True)
    closure(product)
    if args.operation == 'scope':
        if args.retained is None or args.output is None:
            cli.error('--retained and --output are required for scope')
        import operations
        def query(paths):
            return json.loads(operations.run(['nix', 'path-info', '--json', '--recursive', *paths],
                              capture_output=True, text=True, check=True, timeout=120).stdout)
        narrowed = scoped_metadata(product, load(args.retained), query)
        args.output.write_text(json.dumps(narrowed, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
