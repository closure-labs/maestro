# SPDX-License-Identifier: Apache-2.0
"""One gate's immutable verification inputs; never a reusable approval."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
from pathlib import Path

import decision_authority as authority
from security_decisions import canonical_hash


def verifier_version():
    root = Path(__file__).parent
    return canonical_hash({name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                           for name in ('common.py', 'decision_authority.py',
                                        'security_decisions.py', 'decision_packets.py', 'verification_context.py', 'cache_publication.py')})


class VerificationContext:
    def __init__(self):
        self.documents = {}
        self.blobs = {}
        self.graphs = {}
        self.history = {}
        self.origins = {}
        self.members = None
        self.binding = None
        self.revision = None
        self.used = False
        self.invalid = False

    def discard(self):
        self.invalid = True
        self.documents.clear()
        self.blobs.clear()
        self.graphs.clear()
        self.history.clear()
        self.origins.clear()
        self.members = None

    def fail(self, reason):
        self.discard()
        raise ValueError(reason)

    def bind(self, cfg, revision, records, product):
        if self.used or self.invalid:
            self.fail('verification-context-already-used')
        self.used = True
        self.revision = revision
        self.binding = (cfg['repository'], verifier_version(), revision,
                        canonical_hash(cfg), canonical_hash(records), canonical_hash(product))

    def check(self, cfg, revision, records, product):
        current = (cfg['repository'], verifier_version(), revision,
                   canonical_hash(cfg), canonical_hash(records), canonical_hash(product))
        if self.invalid or self.binding is None:
            self.fail('verification-context-invalid')
        for expected, observed, reason in zip(self.binding, current,
                ('repository', 'verifier', 'main', 'policy', 'ledger', 'product')):
            if expected != observed:
                self.fail('verification-context-' + reason + '-changed')

    def repository(self, repository):
        if self.invalid or self.binding is None or self.binding[0] != repository:
            self.fail('verification-context-repository-changed')

    def select(self, kind, cfg, records, identity, validate):
        if self.invalid or self.binding is None:
            self.fail('verification-context-invalid')
        if (canonical_hash(cfg) != self.binding[3]
                or canonical_hash(records) != self.binding[4]):
            self.fail('verification-context-inputs-changed')
        key = (kind, canonical_hash(identity))
        if key not in self.graphs:
            self.graphs[key] = deepcopy(validate())
        return deepcopy(self.graphs[key])

    @contextmanager
    def live_pass(self, api):
        if self.invalid or self.members is not None:
            self.fail('verification-context-live-pass-invalid')
        self.members = authority.approver_members(api)
        try:
            yield
            if authority.approver_members(api) != self.members:
                self.fail('verification-context-membership-changed')
        finally:
            self.members = None
