#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise independent comparison boundaries without running Nix locally."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / '_source'))
import comparison
from test_graph import fixture

PRODUCER = dict(GITHUB_REPOSITORY='closure-labs/maestro', GITHUB_SHA='a' * 40,
                GITHUB_RUN_ID='10', GITHUB_RUN_ATTEMPT='2')


def audit_for(graph):
    return dict(schemaVersion=2, plan='maestro-validation', targetCount=20, failureCount=0,
                results=[dict(name=t['name'], attribute=t['attribute'], status='success',
                              outputs=sorted(t['outputs'].values()))
                         for _, t in comparison.validation_targets(graph)])


class SameCandidateComparison(unittest.TestCase):
    def setUp(self):
        self.graph = fixture()
        self.audit = audit_for(self.graph)

    def test_every_complete_obligation_must_have_exact_outputs(self):
        comparison.validate_audit(self.audit, self.graph)
        changes = [lambda a: a.update(failureCount=1), lambda a: a.update(schemaVersion=3),
                   lambda a: a['results'].pop(), lambda a: a['results'].append(a['results'][0]),
                   lambda a: a['results'][0].update(status='skipped'),
                   lambda a: a['results'][0].update(outputs=['/nix/store/wrong']),
                   lambda a: a['results'][0].update(attribute='checks.x86_64-linux.unknown'),
                   lambda a: a['results'][1].update(**a['results'][0])]
        for change in changes:
            value = copy.deepcopy(self.audit)
            change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                comparison.validate_audit(value, self.graph)

    def test_reference_binds_manifest_timings_graph_and_producer(self):
        with tempfile.TemporaryDirectory() as work, patch.dict(os.environ, PRODUCER):
            root = Path(work)
            (root / 'audit.json').write_text(json.dumps(self.audit))
            (root / 'timings.json').write_text('{"schemaVersion":1}')
            reference = dict(schemaVersion=1, producer=PRODUCER, graphSha256=comparison.digest(self.graph),
                             planSha256='b' * 64, auditSha256=comparison.file_digest(root / 'audit.json'),
                             timingsSha256=comparison.file_digest(root / 'timings.json'))
            path = root / 'reference.json'
            path.write_text(json.dumps(reference))
            identity = comparison.file_digest(path)
            comparison.read_bound_reference(root, self.graph, 'b' * 64, identity)
            for field, value in [('producer', dict(PRODUCER, GITHUB_RUN_ATTEMPT='1')),
                                 ('graphSha256', 'f' * 64), ('planSha256', 'f' * 64), ('schemaVersion', 2)]:
                path.write_text(json.dumps(dict(reference, **{field:value})))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    comparison.read_bound_reference(root, self.graph, 'b' * 64, comparison.file_digest(path))
            path.write_text(json.dumps(reference))
            for filename in ['audit.json', 'timings.json']:
                original = (root / filename).read_bytes()
                (root / filename).write_bytes(original + b' ')
                with self.subTest(filename=filename), self.assertRaises(ValueError):
                    comparison.read_bound_reference(root, self.graph, 'b' * 64, identity)
                (root / filename).write_bytes(original)
            with self.assertRaises(ValueError):
                comparison.read_bound_reference(root, self.graph, 'b' * 64, 'f' * 64)
            (root / 'audit.json').unlink()
            with self.assertRaises(FileNotFoundError):
                comparison.read_bound_reference(root, self.graph, 'b' * 64, identity)

    def test_timings_require_every_successful_obligation_without_conflicts(self):
        timing = dict(schemaVersion=1, plan='maestro-validation', results=[
            dict(attribute=t['attribute'], elapsedSeconds=0, status='success')
            for _, t in comparison.validation_targets(self.graph)])
        comparison.validate_timings(timing, self.graph)
        for mutation in [lambda r: r['results'].pop(), lambda r: r.update(schemaVersion=2),
                         lambda r: r['results'][0].update(elapsedSeconds=float('nan')),
                         lambda r: r['results'][0].update(elapsedSeconds=True),
                         lambda r: r['results'][0].update(status='failure'),
                         lambda r: r['results'][1].update(**r['results'][0])]:
            value = copy.deepcopy(timing)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                comparison.validate_timings(value, self.graph)

    def test_native_derivation_versions_match_only_exact_graph_recipes(self):
        targets = comparison.validation_targets(self.graph)
        old = {t['derivation']: {'outputs': {name: {'path': path} for name,path in t['outputs'].items()}}
               for _,t in targets}
        comparison.verify_recipes(targets, comparison.derivation_records(old))
        current = {'version':4, 'derivations': {key.removeprefix('/nix/store/'): {
            'outputs': {name: {'path': row['path'].removeprefix('/nix/store/')} for name,row in record['outputs'].items()}}
            for key,record in old.items()}}
        comparison.verify_recipes(targets, comparison.derivation_records(current))
        with self.assertRaises(ValueError):
            comparison.derivation_records(dict(current, version=5))
        wrong = copy.deepcopy(old)
        wrong[targets[0][1]['derivation']]['outputs']['out']['path'] = '/nix/store/other'
        with self.assertRaises(ValueError):
            comparison.verify_recipes(targets, wrong)
        with self.assertRaises(ValueError):
            comparison.verify_recipes(targets, {})

    def test_realization_cannot_silently_build_another_product(self):
        target = self.graph['targets']['0']
        row = dict(drvPath=target['derivation'], outputs=target['outputs'])
        comparison.validate_realization([row], target)
        for value in [[], [row,row], [dict(row, drvPath='/nix/store/other.drv')],
                      [dict(row, outputs={'out':'/nix/store/other'})]]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                comparison.validate_realization(value, target)

    def test_comparison_receipt_rejects_missing_results_and_reuse_claims(self):
        rows = [dict(id=key, attribute=t['attribute'], derivation=t['derivation'],
                     outputs=sorted(t['outputs'].values()), status='realized')
                for key,t in comparison.validation_targets(self.graph)]
        receipt = dict(schemaVersion=1, producer=PRODUCER, status='matched',
                       graphSha256=comparison.digest(self.graph), planSha256='b'*64,
                       gatingEnabled=False, retainedEvidenceReuseAuthorized=False,
                       targetCount=20, graphResults=rows)
        comparison.validate_comparison(receipt, self.graph, 'b'*64, PRODUCER)
        mutations = [lambda r: r['graphResults'].pop(),
                     lambda r: r['graphResults'][0].update(status='skipped'),
                     lambda r: r['graphResults'][0].update(derivation='/nix/store/other.drv'),
                     lambda r: r.update(producer=dict(PRODUCER,GITHUB_SHA='f'*40)),
                     lambda r: r.update(gatingEnabled=True),
                     lambda r: r.update(retainedEvidenceReuseAuthorized=True),
                     lambda r: r.update(planSha256='f'*64)]
        for mutation in mutations:
            value = copy.deepcopy(receipt)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                comparison.validate_comparison(value, self.graph, 'b'*64, PRODUCER)


if __name__ == '__main__':
    unittest.main()
