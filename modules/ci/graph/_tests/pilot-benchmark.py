#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[4] / 'modules/ci/authority/_source/pilot-benchmark.py'


class Benchmark(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.input = Path(self.root.name) / 'jobs.json'
        def job(name, seconds):
            return dict(name=name, run_id=1, run_url='https://api.github.com/repos/closure-labs/maestro/actions/runs/1',
                        conclusion='success', started_at='2026-10-14T00:00:00Z', completed_at=f'2026-10-14T00:00:{seconds:02d}Z')
        route = job('Audit repository and route downstream work', 20)
        route['steps'] = [job('Validate repository', 10)]
        self.data = dict(jobs=[route, job('Qualify installer media and evidence', 30), job('Scan qualified dependency inventories', 10)])

    def benchmark(self, overhead=0):
        self.input.write_text(json.dumps(self.data))
        return subprocess.run([sys.executable, str(SCRIPT), str(self.input), '--audit-job-overhead-seconds', str(overhead)],
                              text=True, capture_output=True)

    def test_overlap_preserves_longer_audit_join_and_labels_model(self):
        report = json.loads(self.benchmark().stdout)
        self.assertEqual(report['modeled_seconds']['critical_path_reduction'], 10)
        self.assertIn('not observed', report['evidence_kind'])
        slower = json.loads(self.benchmark(50).stdout)
        self.assertEqual(slower['modeled_seconds']['critical_path_reduction'], -10)
        self.assertEqual(slower['modeled_seconds']['additional_runner_work'], 50)

    def test_rejects_failed_or_non_maestro_evidence(self):
        self.data['jobs'][0]['steps'][0]['conclusion'] = 'failure'
        self.assertNotEqual(self.benchmark().returncode, 0)
        self.data['jobs'][0]['steps'][0]['conclusion'] = 'success'
        self.data['jobs'][1]['run_url'] = 'https://api.github.com/repos/attacker/fake/actions/runs/1'
        self.assertNotEqual(self.benchmark().returncode, 0)


unittest.main()
