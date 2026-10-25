# SPDX-License-Identifier: Apache-2.0
"""Official recovery discovery tolerates separately approved rolling products."""
from copy import deepcopy
import datetime as dt
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

AUTOMATION = Path(__file__).resolve().parents[2] / 'nix/automation'
sys.path.insert(0, str(AUTOMATION / 'decisions'))
spec = importlib.util.spec_from_file_location('official_selection', AUTOMATION / 'decision-retained.py')
retained = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retained)


class OfficialSelection(unittest.TestCase):
    def setUp(self):
        self.producer = {'repository': 'closure-labs/maestro', 'revision': 'a' * 40,
                         'sourceRevision': 'a' * 40, 'workflow': '.github/workflows/release.yml',
                         'runId': 123, 'runAttempt': 1}
        self.official = {'kind': 'release-product', 'payload': {
            'disposition': 'accepted', 'rationale': 'Reviewed exact official bytes', 'supersedes': [],
            'product': {'revision': 'a' * 40, 'assets': {'maestro-v1.2.3.iso.sha256': 'b' * 64}},
            'packet': {'reference': retained.packets.REGISTRY + '@sha256:' + 'c' * 64,
                       'sha256': 'd' * 64, 'producer': self.producer}}}
        self.rolling = deepcopy(self.official)
        self.rolling['payload']['product'] = {'revision': 'e' * 40, 'assets': {}}

    def records(self, *proposals):
        return {retained.canonical_hash(p): p for p in proposals}

    def test_official_selection_ignores_an_active_rolling_product(self):
        selected = retained.select({}, self.records(self.official, self.rolling), {}, release_only=True)
        self.assertEqual(selected, (retained.canonical_hash(self.official), self.official))

    def test_pending_rolling_does_not_displace_current_official_selection(self):
        selected = retained.select({}, self.records(self.official), self.records(self.rolling), release_only=True)
        self.assertEqual(selected[1], self.official)

    def test_only_rolling_records_produce_no_official_candidate(self):
        with self.assertRaises(retained.NoCandidate):
            retained.select({}, self.records(self.rolling), {}, release_only=True)

    def test_explicit_rolling_request_cannot_enter_official_selection(self):
        with self.assertRaises(ValueError):
            retained.select({}, self.records(self.official, self.rolling), {}, release_only=True,
                            proposal_hash=retained.canonical_hash(self.rolling))

    def test_published_official_with_rolling_produces_no_candidate(self):
        with self.assertRaises(retained.NoCandidate):
            retained.select({}, self.records(self.official, self.rolling), {}, release_only=True,
                            published_tags={'v1.2.3'})

    def test_malformed_assets_do_not_become_rolling_exclusions(self):
        for assets in (None, [], {'unversioned.iso.sha256': 'b' * 64},
                       {'maestro-v1.2.3.iso.sha256': 'b' * 64,
                        'maestro-v2.0.0.iso.sha256': 'c' * 64}):
            bad = deepcopy(self.official)
            bad['payload']['product']['assets'] = assets
            with self.subTest(assets=assets), self.assertRaises(ValueError):
                retained.select({}, self.records(bad), {}, release_only=True)

    def test_missing_assets_are_not_a_rolling_product(self):
        bad = deepcopy(self.official)
        del bad['payload']['product']['assets']
        with self.assertRaises(ValueError):
            retained.select({}, self.records(bad), {}, release_only=True)

    def test_different_official_versions_select_newest_and_keep_explicit_history(self):
        other = deepcopy(self.official)
        other['payload']['product']['assets'] = {'maestro-v2.0.0.iso.sha256': 'f' * 64}
        records = self.records(self.official, other, self.rolling)
        self.assertEqual(retained.select({}, records, {}, release_only=True)[1], other)
        self.assertEqual(retained.select({}, records, {}, release_only=True,
                         proposal_hash=retained.canonical_hash(self.official))[1], self.official)

    def test_conflicting_products_for_same_version_require_explicit_selection(self):
        other = deepcopy(self.official)
        other['payload']['product']['assets'] = {'maestro-v1.2.3.iso.sha256': 'f' * 64}
        with self.assertRaisesRegex(ValueError, 'unambiguous'):
            retained.select({}, self.records(self.official, other, self.rolling), {}, release_only=True)

    def test_published_inspection_ignores_rolling_before_metadata_reads(self):
        with patch.object(retained.packets, 'metadata', side_effect=AssertionError('Unneeded metadata read')):
            self.assertEqual(retained.current_published_products(
                {}, self.records(self.official, self.rolling), set()), set())
            self.assertEqual(retained.current_published_products(
                {}, self.records(self.rolling), {'v1.2.3'}), set())

    def test_published_fresh_official_remains_suppressed_alongside_rolling(self):
        observed = {'repository': 'closure-labs/maestro', 'revision': 'a' * 40,
                    'producer': {k: v for k, v in self.producer.items()
                                 if k not in ('repository', 'sourceRevision')}}
        expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
        with patch.object(retained.packets, 'metadata', return_value=observed) as metadata, \
                patch.object(retained.scheduling, 'observation_expiry', return_value=expiry):
            self.assertEqual(retained.current_published_products(
                {'repository': 'closure-labs/maestro'}, self.records(self.official, self.rolling),
                {'v1.2.3'}), {retained.canonical_hash(self.official['payload']['product'])})
            metadata.assert_called_once()

    def test_malformed_published_assets_still_block(self):
        for assets in (None, [], {'not-an-official-version': 'b' * 64}):
            bad = deepcopy(self.official)
            bad['payload']['product']['assets'] = assets
            with self.subTest(assets=assets), self.assertRaises(ValueError):
                retained.current_published_products({}, self.records(bad, self.rolling), set())

    def test_revoked_official_is_not_replaced_by_rolling(self):
        revoked = deepcopy(self.official)
        revoked['payload']['disposition'] = 'revoked'
        with self.assertRaises(retained.NoCandidate):
            retained.select({}, self.records(revoked, self.rolling), {}, release_only=True)


if __name__ == '__main__':
    unittest.main()
