#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import copy
import hashlib
import json
import tempfile
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

    def test_producer_emits_explicit_iso_inventory_binding_after_boot_validation(self):
        self.route['qualification']['mode']='reuse'
        self.graph.update(mode='complete',gatingEnabled=False)
        self.boot.update(disposition='verified-retained',bootLogSha256=None,graphSha256=graph.digest(self.graph))
        plan=dict(mode='complete',gatingEnabled=False,candidateRevision=PRODUCER['GITHUB_SHA'],
            candidateGraphSha256=graph.digest(self.graph),decisions={'routePlanSha256':graph.digest(self.route)})
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for directory in ('ci-graph','complete-audit','security-report'):(root/directory).mkdir()
            for name,value in (('ci-graph/candidate.json',self.graph),('ci-graph/plan.json',plan),
                ('boot-result.json',self.boot),('complete-audit/reference.json',{}),
                ('security-report/security-result.json',{'status':'complete','scannerHealth':'healthy'})):
                (root/name).write_text(json.dumps(value))
            sha=lambda name:hashlib.sha256((root/name).read_bytes()).hexdigest()
            env=dict(PRODUCER,GRAPH_PLAN_SHA256=sha('ci-graph/plan.json'),CI_PLAN=json.dumps(self.route),
                BOOT_RESULT_SHA256=sha('boot-result.json'),INVENTORY_TRANSFER_SHA256='f'*64,
                AUDIT_REFERENCE_SHA256=sha('complete-audit/reference.json'),
                AUDIT_RESULT='success',SCAN_RESULT='success',QUALIFICATION_RESULT='success')
            before=Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ,env,clear=True),patch.object(result,'read_bound_reference',return_value=({'auditSha256':'e'*64},{})) as reference:
                    result.main()
                    emitted=json.loads(Path('ci-result.json').read_text())
                    self.assertEqual(emitted['schemaVersion'],2)
                    self.assertEqual(emitted['validationMode'],'complete-audit')
                    self.assertEqual(emitted['completeAuditSha256'],'e'*64)
                    self.assertEqual(emitted['jobs'],{k:'success' for k in ('AUDIT_RESULT','SCAN_RESULT','QUALIFICATION_RESULT')})
                    self.assertNotIn('comparisonSha256',emitted)
                    reference.assert_called_once()
                    self.assertEqual(emitted['inventoryIsoBinding'],dict(schemaVersion=1,producer=PRODUCER,
                        inventorySha256='f'*64,isoSha256='d'*64))
                    self.assertEqual(emitted['boot']['disposition'],'verified-retained')
                    self.assertIsNone(emitted['boot']['bootLogSha256'])
                    Path('boot-result.json').write_text('{}')
                    with self.assertRaisesRegex(ValueError,'Boot result digest mismatch'):result.main()
            finally:os.chdir(before)

    def test_explicit_iso_binding_rejects_wrong_producer_and_malformed_digests(self):
        for boot,inventory in ((dict(self.boot,producer={}), 'f'*64),
                               (dict(self.boot,isoSha256=None),'f'*64),
                               (self.boot,''),(self.boot,'g'*64)):
            with self.subTest(boot=boot,inventory=inventory),self.assertRaises((ValueError,TypeError)):
                result.inventory_iso_binding(boot,inventory,PRODUCER)

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
