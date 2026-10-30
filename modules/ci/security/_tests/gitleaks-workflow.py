#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Small Git graphs verify upstream CLI scope and unprivileged workflow boundaries."""
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
WORKFLOW = ROOT / '.github/workflows/repository-secret-scan.yml'

def scan_script():
    text = WORKFLOW.read_text().split('      - name: Scan complete introduced commit range\n', 1)[1].split('        run: |\n', 1)[1]
    rows = []
    for line in text.splitlines():
        if line and not line.startswith('            ') and not line.startswith('          '):
            break
        rows.append(line[10:])
    return '\n'.join(rows) + '\n'

class RangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'candidate'
        self.repo.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
        self.git('init', '-q', '-b', 'main')
        self.commit('base.txt', 'pre-existing-marker\n')
        self.base = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-q', '-b', 'side')
        self.commit('side.txt', 'side-introduced-then-deleted-marker\n')
        self.side = self.git('rev-parse', 'HEAD')
        self.git('rm', '-q', 'side.txt')
        self.git('commit', '-qm', 'remove side fixture')
        self.git('checkout', '-q', 'main')
        self.commit('main.txt', 'main-introduced-marker\n')
        self.git('merge', '--no-ff', '--no-commit', 'side')
        self.commit('merge-only.txt', 'merge-only-resolution-marker\n')
        self.head = self.git('rev-parse', 'HEAD')
        (self.root / 'controller').mkdir()
        (self.root / 'controller/.gitleaks.toml').write_bytes((ROOT / '.gitleaks.toml').read_bytes())
        self.runtime = self.root / 'runtime'
        (self.runtime / 'gitleaks').mkdir(parents=True)
        binary = self.runtime / 'gitleaks/gitleaks'
        binary.write_text('#!' + sys.executable + '\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ["ARG_LOG"]).write_text(json.dumps(sys.argv[1:]))\nprint("DO-NOT-EXPOSE-FIXTURE-PAYLOAD")\nsys.exit(int(os.environ.get("SCANNER_EXIT","0")))\n')
        binary.chmod(0o755)

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', *args], cwd=self.repo, env=self.env, stderr=subprocess.DEVNULL, text=True).strip()

    def commit(self, name, text):
        (self.repo / name).write_text(text)
        self.git('add', name)
        self.git('commit', '-qm', 'synthetic fixture')

    def run_scan(self, **values):
        env = dict(self.env, EVENT_NAME='pull_request', BASE_SHA=self.base, HEAD_SHA=self.head,
                   RUNNER_TEMP=str(self.runtime), GITHUB_WORKSPACE=str(self.root), ARG_LOG=str(self.root / 'args.json'))
        env.update(values)
        return subprocess.run(['bash', '-c', scan_script()], cwd=self.repo, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_complete_graph_and_merge_only_content(self):
        result = self.run_scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads((self.root / 'args.json').read_text())
        opts = next(a.split('=', 1)[1] for a in args if a.startswith('--log-opts='))
        self.assertNotIn('--first-parent ', opts)
        self.assertNotIn('--no-merges', opts)
        patch = self.git('log', '-p', '-U0', *opts.split())
        for marker in ['side-introduced-then-deleted-marker', 'merge-only-resolution-marker', 'main-introduced-marker']:
            self.assertIn('+' + marker, patch)
        self.assertNotIn('+pre-existing-marker', patch)
        self.assertIn(self.side, patch)
        self.assertNotIn('DO-NOT-EXPOSE', result.stdout + result.stderr)
        self.assertIn('--redact=100', args)
        self.assertFalse(any(a.startswith('--report') or a.startswith('--baseline') for a in args))
        self.assertEqual(self.run_scan(EVENT_NAME='merge_group').returncode, 0)

    def test_missing_bad_equal_and_wrong_checkout_fail_before_scanner(self):
        for values in [{'BASE_SHA': ''}, {'BASE_SHA': '1' * 40}, {'HEAD_SHA': 'not-a-sha'},
                       {'BASE_SHA': self.head}, {'HEAD_SHA': self.base}, {'EVENT_NAME': 'workflow_run'}]:
            with self.subTest(values=values):
                result = self.run_scan(**values)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'args.json').exists())

    def test_diverged_pr_base_is_valid_but_queue_base_must_be_ancestor(self):
        self.git('checkout', '-q', '-b', 'new-base', self.base)
        self.commit('new-base.txt', 'new base data\n')
        diverged = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-q', 'main')
        self.assertEqual(self.run_scan(BASE_SHA=diverged).returncode, 0)
        self.assertNotEqual(self.run_scan(BASE_SHA=diverged, EVENT_NAME='merge_group').returncode, 0)

    def test_real_pinned_cli_detects_introduced_then_deleted_secret(self):
        scanner = os.environ.get('GITLEAKS_BIN') or shutil.which('gitleaks')
        self.assertTrue(scanner, 'The pinned native Gitleaks executable is required')
        self.assertEqual(subprocess.check_output([scanner, 'version'], text=True).strip(), '8.30.1')
        binary = self.runtime / 'gitleaks/gitleaks'
        binary.unlink()
        binary.symlink_to(scanner)
        # Pre-existing debt is outside the range even when still in the tree.
        # Public synthetic scanner marker; never substitute a live credential.
        synthetic_pat = 'gh' + 'p_' + ''.join(('7ByR9KxW3cTa', '8HsM2nVp6QdE', '4LfZ0uJ5iGoS'))
        self.commit('old.txt', 'token = "' + synthetic_pat + '"\n')
        self.base = self.git('rev-parse', 'HEAD')
        self.commit('new.txt', 'ordinary content\n')
        self.head = self.git('rev-parse', 'HEAD')
        self.assertEqual(self.run_scan().returncode, 0)
        self.commit('incoming.txt', 'token = "' + synthetic_pat + '" # gitleaks:allow\n')
        self.git('rm', '-q', 'incoming.txt')
        self.git('commit', '-qm', 'remove incoming fixture')
        self.head = self.git('rev-parse', 'HEAD')
        result = self.run_scan()
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(synthetic_pat, result.stdout + result.stderr)

    def test_shallow_checkout_fails(self):
        (self.repo / '.git/shallow').write_text(self.base + '\n')
        self.assertNotEqual(self.run_scan().returncode, 0)
        self.assertFalse((self.root / 'args.json').exists())

    def test_findings_errors_and_timeouts_never_pass_or_leak(self):
        for status in [1, 2, 124, 137]:
            result = self.run_scan(SCANNER_EXIT=str(status))
            self.assertEqual(result.returncode, status)
            self.assertNotIn('DO-NOT-EXPOSE', result.stdout + result.stderr)


class WorkflowBoundaryTests(unittest.TestCase):
    def test_read_only_cli_without_candidate_execution_or_suppression(self):
        text = WORKFLOW.read_text()
        for value in ['workflow_call:', 'Repository historical audit (nonblocking debt)',
                      'persist-credentials: false', 'ref: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}',
                      '--ignore-gitleaks-allow', '--gitleaks-ignore-path', '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb']:
            self.assertIn(value, text)
        for absent in ['secrets.', 'write\n', 'continue-on-error:', 'upload-artifact', 'pull_request_target:',
                       'workflow_run:', '--baseline-path', '--max-target-megabytes', 'create-github-app-token', 'nix run', './candidate/']:
            self.assertNotIn(absent, text)
        self.assertEqual(text.count('persist-credentials: false'), 4)

    def test_ci_verdict_always_waits_for_scan_and_checks_its_result(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('uses: $/.github/workflows/repository-secret-scan.yml', ci)
        verdict = ci.split('  verdict:', 1)[1]
        self.assertIn('      - incoming_secret_scan', verdict)
        self.assertIn('INCOMING_SECRET_RESULT: ${{ needs.incoming_secret_scan.result }}', verdict)
        leaf = (ROOT / 'modules/ci/checks/_source/verdict.sh').read_text()
        self.assertIn('pull_request|merge_group) test "${INCOMING_SECRET_RESULT:?}" = success', leaf)

    def test_cli_exception_is_bound_to_reviewed_workflow_bytes(self):
        import hashlib
        policy = (ROOT / 'modules/ci/checks/_lib/repository-policy.nix').read_text()
        self.assertIn(hashlib.sha256(WORKFLOW.read_bytes()).hexdigest(), policy)

if __name__ == '__main__': unittest.main()
