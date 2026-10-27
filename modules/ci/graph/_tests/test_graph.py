#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / '_source'))

spec = importlib.util.spec_from_file_location('graph', Path(__file__).parents[1] / '_source/graph.py')
graph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graph)


def fixture():
    return dict(schemaVersion=1, mode='shadow', gatingEnabled=False, system='x86_64-linux', targets={
        str(i): dict(id=str(i), name=str(i), owner='ci/checks', attribute=f'checks.x86_64-linux.t{i}',
                     derivation=f'/nix/store/{i:032x}-target.drv', outputs={'out': f'/nix/store/{i:032x}-target'},
                     dependencies=[], phases=['validation'], requirements=['deterministic']) for i in range(20)})


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.candidate, self.base = fixture(), fixture()

    def plan(self, **kwargs):
        return graph.plan(self.candidate, self.base, 'a' * 40, 'b' * 40, ['docs/navigation.md'], **kwargs)

    def test_equal_derivations_never_authorize_a_skip(self):
        result = self.plan()
        self.assertEqual(len(result['equalDerivations']), 20)
        self.assertFalse(result['evidenceReuseAuthorized'])
        self.assertTrue(result['completeValidationRequired'])

    def test_change_uses_derivation_not_directory(self):
        self.candidate['targets']['0']['derivation'] = '/nix/store/' + 'f' * 32 + '-changed.drv'
        self.assertEqual(self.plan()['changedDerivations'], ['0'])

    def test_unknown_versions_missing_and_unmapped_targets_fall_back(self):
        for mutation in [lambda g: g.update(schemaVersion=2), lambda g: g.update(targets={}),
                         lambda g: g['targets']['0'].update(dependencies=['absent'])]:
            self.candidate = fixture()
            mutation(self.candidate)
            result = self.plan()
            self.assertTrue(result['fallbackReasons'])
            self.assertTrue(result['completeValidationRequired'])

    def test_cycles_duplicate_owners_missing_outputs_and_obligations_rejected(self):
        mutations = [lambda g: g['targets']['0'].update(dependencies=['0']),
                     lambda g: g['targets']['0'].update(attribute=g['targets']['1']['attribute']),
                     lambda g: g['targets']['0'].update(outputs={}),
                     lambda g: g['targets'].pop('0')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = fixture()
                mutation(candidate)
                with self.assertRaises(ValueError):
                    graph.validate(candidate)

    def test_force_and_forks_preserve_complete_validation(self):
        result = self.plan(force=True, fork=True)
        self.assertEqual(result['fallbackReasons'], ['force-build', 'fork-restrictions'])
        self.assertTrue(result['completeValidationRequired'])

    def test_unmapped_input_and_immutable_revisions(self):
        result = graph.plan(self.candidate, self.base, 'a' * 40, 'b' * 40, ['unknown.recipe'])
        self.assertIn('unmapped-inputs', result['fallbackReasons'])
        with self.assertRaises(ValueError):
            graph.plan(self.candidate, self.base, 'main', 'b' * 40)

    def test_ownership_is_deterministic(self):
        self.assertEqual(graph.ownership(self.candidate), graph.ownership(copy.deepcopy(self.candidate)))


if __name__ == '__main__':
    unittest.main()
