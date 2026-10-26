#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / '_source'))
import graph
import transfer
import result

PRODUCER = dict(GITHUB_REPOSITORY='closure-labs/maestro', GITHUB_SHA='a' * 40,
                GITHUB_RUN_ID='1', GITHUB_RUN_ATTEMPT='1')


class BoundResults(unittest.TestCase):
    def setUp(self):
        self.graph = {'policy': {'boot': 'b' * 64}}
        self.route = {'qualification': {'mode': 'qualify-media', 'media_input': 'c' * 64}}
        self.boot = dict(schemaVersion=1, producer=PRODUCER, graphSha256=graph.digest(self.graph),
                         mediaInput='c' * 64, verifierSha256='b' * 64, isoSha256='d' * 64,
                         bootLogSha256='e' * 64, disposition='executed')

    def test_boot_result_binds_producer_policy_and_actual_execution(self):
        result.validate_boot(self.boot, self.graph, self.route, PRODUCER)
        for key, value in [('producer', dict(PRODUCER, GITHUB_RUN_ATTEMPT='2')),
                           ('graphSha256', 'f' * 64), ('mediaInput', 'f' * 64),
                           ('verifierSha256', 'f' * 64), ('bootLogSha256', None),
                           ('disposition', 'verified-retained')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                result.validate_boot(dict(self.boot, **{key: value}), self.graph, self.route, PRODUCER)

    def test_retained_boot_cannot_be_reported_as_executed(self):
        self.route['qualification']['mode'] = 'reuse'
        with self.assertRaises(ValueError):
            result.validate_boot(self.boot, self.graph, self.route, PRODUCER)
        self.boot.update(disposition='verified-retained', bootLogSha256=None)
        result.validate_boot(self.boot, self.graph, self.route, PRODUCER)

    def test_transfer_rejects_changed_producer_derivation_and_missing_roots(self):
        target = dict(attribute='packages.x86_64-linux.fixture', derivation='fixture.drv', outputs={'out': '/nix/store/fixture'})
        manifest = dict(schemaVersion=2, phase='appliance', producer=PRODUCER, graphSha256='f' * 64,
                        targets=[target], roots=[dict(storePath='/nix/store/fixture', narHash='identity')], transport={},
                        files={name:'e' * 64 for name in transfer.INDEX_FILES['appliance']}, evidenceFiles={}, isoSha256=None)
        with patch.dict(os.environ, PRODUCER):
            transfer.validate(manifest, 'appliance', [target], 'f' * 64)
            for key, value in [('producer', dict(PRODUCER, GITHUB_SHA='b' * 40)),
                               ('targets', [dict(target, derivation='different.drv')]), ('roots', []),
                               ('phase', 'installer'), ('schemaVersion', 1), ('files', {}), ('evidenceFiles', {'unexpected':'f' * 64})]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    transfer.validate(dict(manifest, **{key: value}), 'appliance', [target], 'f' * 64)


if __name__ == '__main__':
    unittest.main()
