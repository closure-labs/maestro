# SPDX-License-Identifier: Apache-2.0
"""Explicit multi-leaf recovery guards; these checks grant no new acceptance."""
import tempfile
import json
from pathlib import Path

import common
import recovery_context
import decision_packets as packets
from security_decisions import canonical_hash, normalize_findings

FIELDS = {'schema', 'mainRevision', 'graphHash', 'policyHash', 'parents', 'rationale', 'disposition'}


def load_request(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            common.require(key not in result, 'Duplicate recovery request JSON key')
            result[key] = value
        return result
    value = json.loads(text, object_pairs_hook=unique,
                       parse_constant=lambda _: common.require(False, 'Nonfinite recovery JSON number'))
    shape(value)
    return value


def shape(request):
    common.require(isinstance(request, dict) and set(request) == FIELDS
                   and type(request['schema']) is int and request['schema'] == 1,
                   'Explicit complete security recovery request required')
    common.require(isinstance(request['mainRevision'], str) and common.SHA.fullmatch(request['mainRevision'])
                   and all(isinstance(request[k], str) and common.HASH.fullmatch(request[k])
                           for k in ('graphHash', 'policyHash')),
                   'Exact recovery graph, policy and main snapshot required')
    parents = request['parents']
    common.require(isinstance(parents, list) and len(parents) >= 2
                   and all(isinstance(p, str) and common.HASH.fullmatch(p) for p in parents)
                   and parents == sorted(set(parents)), 'Recovery requires sorted unique complete parents')
    common.require(isinstance(request['rationale'], str) and request['rationale'].strip()
                   and request['disposition'] in ('accepted', 'rejected'),
                   'Explicit recovery rationale and disposition required')


def evidence(cfg, proposal):
    """Authenticate each original packet independently, including differing producers."""
    payload = proposal['payload']
    packet = payload.get('packet')
    common.require(isinstance(packet, dict) and set(packet) == {'reference', 'sha256', 'producer'},
                   'Complete historical packet proof required')
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / 'packet'
        manifest = packets.fetch(packet['reference'], root, packet['sha256'])
        common.require(manifest['producer'] == packet['producer'], 'Historical packet producer differs')
        native = common.scans(root / 'scans.json', cfg, allow_expired=True)
        producer = dict(native['producer'], repository=cfg['repository'],
                        revision=native['producer'].get('revision', native['revision']),
                        sourceRevision=native['revision'])
        expected = {p: normalize_findings(s, p) for p, s in native['profiles'].items()}
        common.require(packet['producer'] == producer and set(expected) == set(cfg['profiles'])
                       and payload['profiles'] == expected
                       and common.accepted_contexts(payload) == common.security_contexts(native),
                       'Historical proof differs from complete authenticated findings or contexts')


def security_leaves(cfg, records, proof_context=None):
    """Enumerate explicitly; reuse the ordinary checker on every leaf ancestry.

    No normal selector interface changes or synthetic decision records are
    needed. Detect disconnected cycles too, before inspecting individual trees.
    """
    candidates = {h: p for h, p in records.items()
                  if p['kind'] in ('security-findings', 'security-revocation')}
    ancestors, visiting, superseded = {}, set(), set()
    def visit(digest):
        common.require(digest not in visiting, 'Cyclic decision supersession')
        if digest in ancestors:
            return ancestors[digest]
        visiting.add(digest)
        parents = candidates[digest]['payload'].get('supersedes', [])
        common.require(isinstance(parents, list)
                       and all(isinstance(p, str) and p in candidates and p != digest for p in parents)
                       and len(set(parents)) == len(parents), 'Invalid supersession parents')
        selected = {digest}
        for parent in parents:
            selected.update(visit(parent))
        superseded.update(parents)
        visiting.remove(digest)
        ancestors[digest] = selected
        return selected
    for digest in candidates:
        visit(digest)
    leaves = {}
    for digest in sorted(set(candidates) - superseded):
        selected, value = common.security_graph(cfg, {h: candidates[h] for h in ancestors[digest]}, context=proof_context)
        common.require(selected == digest, 'Invalid recovery leaf ancestry')
        leaves[digest] = value
    return leaves


@recovery_context.scoped('recovery-validation')
def validate(cfg, request, *, verify_packets=True):
    shape(request)
    state = recovery_context.current()
    state.counts['validations'] += 1
    common.require(state.counts['validations'] <= recovery_context.MAX_PASSES, 'Recovery validation budget exceeded')
    state.counts['ledgerReads'] += 1
    state.phase('ledger-observation')
    revision, records = common.ledger(cfg)
    common.require(revision == request['mainRevision'] and canonical_hash(records) == request['graphHash'],
                   'Security recovery graph snapshot changed')
    common.require(canonical_hash(cfg) == request['policyHash'], 'Security recovery policy snapshot changed')
    state.counts['policyReads'] += 1
    state.phase('policy-observation')
    policy = common.authority.document_at(common.authority.github_api, cfg['repository'], cfg['policyPath'], revision)
    common.require(policy == cfg, 'Security recovery current policy changed')
    state.counts['ruleChecks'] += 1
    state.phase('rules-observation')
    common.required_check(cfg)
    state.bind(cfg, request, revision, records)
    state.phase('historical-provenance')
    leaves = security_leaves(cfg, records, state)
    common.require(sorted(leaves) == request['parents'], 'Security recovery requires complete current active parent set')
    scopes = [(p['payload']['profiles'], common.accepted_contexts(p['payload'])) for p in leaves.values()]
    common.require(all(p['payload']['disposition'] == 'accepted' for p in leaves.values())
                   and all(scope == scopes[0] for scope in scopes),
                   'Security recovery requires equal accepted findings and contexts')
    # Superseded history needs immutable provenance, while every active parent
    # must retain current human authority. No departure/revocation waiver here.
    state.phase('live-parents')
    for proposal in leaves.values():
        state.counts['liveParents'] += 1
        common.authorize(cfg, proposal)
    if verify_packets:
        state.phase('historical-packets')
        for proposal in records.values():
            if proposal['kind'] in ('security-findings', 'security-revocation'):
                common.historical_provenance(cfg, proposal, context=state)
                evidence(cfg, proposal)
                state.counts['packetProofs'] += 1
                state.phase('historical-packets', proofHash=canonical_hash(proposal))
    state.counts['mainReads'] += 1
    state.phase('final-main-observation')
    common.require(common.main_revision(cfg) == revision, 'Security recovery graph snapshot changed')
    state.phase('snapshot-verified')
    return leaves


def scope(payload, leaves):
    expected = next(iter(leaves.values()))['payload']
    common.require(payload['profiles'] == expected['profiles']
                   and common.accepted_contexts(payload) == common.accepted_contexts(expected),
                   'Fresh recovery evidence differs from parent findings or contexts')


@recovery_context.scoped('proposal-validation')
def proposal(cfg, value, *, verify_packets=True):
    payload = value['payload']
    request = payload['recovery']
    shape(request)
    common.require(value['kind'] == 'security-findings'
                   and payload.get('supersedes') == request['parents']
                   and payload.get('rationale') == request['rationale']
                   and payload.get('disposition') == request['disposition'],
                   'Recovery proposal differs from explicit request')
    leaves = validate(cfg, request, verify_packets=verify_packets)
    scope(payload, leaves)
    return request['mainRevision']


def fresh(cfg, native):
    common.fresh_scan(native, cfg)
    common.verify_producer(cfg, native['producer'], native['revision'], require_main=True)
    state = recovery_context.current()
    if state is not None:
        state.phase('evidence-verified')
