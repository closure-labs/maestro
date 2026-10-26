#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('summary', Path(__file__).parents[1] / '_source/summary.py')
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class ObservedSummary(unittest.TestCase):
    def test_native_activities_are_deduplicated_without_inventing_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            drv, out = '/nix/store/' + 'a' * 32 + '-test.drv', '/nix/store/' + 'b' * 32 + '-test'
            for name, kind, path in [('build', 105, drv), ('substitute', 108, out), ('duplicate', 105, drv)]:
                data = root / (name + '.jsonl')
                data.write_text('@nix ' + json.dumps(dict(action='start', type=kind, fields=[path])) + '\n')
                data.with_name(data.name + '.result.json').write_text('{"exitCode":0}')
            value = summary.activities(root)
            self.assertEqual(value['buildDerivationsObserved'], [drv])
            self.assertEqual(value['substitutionPathsObserved'], [out])
            self.assertEqual(value['incompleteOrFailedTraceCount'], 0)
            (root / 'no-execution.jsonl').write_text('ordinary progress text\n')
            value = summary.activities(root)
            self.assertEqual(value['incompleteOrFailedTraceCount'], 1)
            self.assertEqual(value['buildDerivationsObserved'], [drv])

    def test_completed_and_running_timings_are_distinguished(self):
        page = {'jobs': [dict(name='Build appliance', status='completed', conclusion='success',
                             started_at='2026-10-26T00:00:00Z', completed_at='2026-10-26T00:00:10Z'),
                         dict(name='Required CI verdict', status='in_progress', conclusion=None,
                              started_at='2026-10-26T00:00:10Z', completed_at=None)]}
        rows = summary.summarize([page], dt.datetime(2026, 10, 26, 0, 0, 20, tzinfo=dt.timezone.utc))
        self.assertEqual([row['elapsedSeconds'] for row in rows], [10, 10])
        self.assertEqual([row['completed'] for row in rows], [True, False])


if __name__ == '__main__':
    unittest.main()
