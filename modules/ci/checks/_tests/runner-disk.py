#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the real preflight with mocked capacity/privilege and disposable SDKs."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location('runner_disk', ROOT / '.github/actions/setup-nix/disk.py')
DISK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DISK)


class DiskPreparation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        self.sdks = (self.root / 'android', self.root / 'dotnet')
        for directory in self.sdks:
            directory.mkdir()
            (directory / 'unused-sdk').write_text('disposable fixture')
        self.sentinel = self.workspace / 'evidence'
        self.sentinel.write_text('retain this evidence')
        self.environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                            'RUNNER_OS': 'Linux', 'GITHUB_WORKSPACE': str(self.workspace)}

    def run_prepare(self, free, remove=None, environment=None):
        capacities = [SimpleNamespace(free=value) for value in free]
        with (patch.dict(os.environ, environment or self.environment, clear=True),
              patch.object(DISK, 'UNUSED_SDKS', self.sdks),
              patch.object(DISK.shutil, 'disk_usage', side_effect=capacities),
              patch.object(DISK.subprocess, 'run', side_effect=remove) as command,
              contextlib.redirect_stdout(io.StringIO())):
            DISK.prepare()
            return command.call_args_list

    def remove(self, command, *, check):
        self.assertTrue(check)
        self.assertEqual(command[:6], ['sudo', '-n', 'rm', '-rf', '--one-file-system', '--'])
        self.assertIn(Path(command[6]), self.sdks)
        shutil.rmtree(command[6])

    def test_production_boundaries_are_fixed_and_reserve_is_explicit(self):
        self.assertEqual(DISK.UNUSED_SDKS, (Path('/usr/local/lib/android'), Path('/usr/share/dotnet')))
        self.assertEqual(DISK.MINIMUM_FREE_BYTES, 20 * 1024 ** 3)
        action = (ROOT / '.github/actions/setup-nix/action.yml').read_text()
        self.assertLess(action.index('run: python3 "$GITHUB_ACTION_PATH/disk.py"'), action.index('uses: DeterminateSystems/'))
        self.assertIn('python3 modules/ci/checks/_tests/runner-disk.py', (ROOT / 'modules/ci/checks/contracts.nix').read_text())

    def test_sufficient_capacity_never_deletes(self):
        self.assertEqual(self.run_prepare([DISK.MINIMUM_FREE_BYTES]), [])
        self.assertTrue(all(directory.exists() for directory in self.sdks))

    def test_low_disk_reclaims_only_needed_fixed_sdk_and_keeps_evidence(self):
        calls = self.run_prepare([2 * 1024 ** 2, DISK.MINIMUM_FREE_BYTES], self.remove)
        self.assertEqual(len(calls), 1)
        self.assertFalse(self.sdks[0].exists())
        self.assertTrue(self.sdks[1].exists())
        self.assertEqual(self.sentinel.read_text(), 'retain this evidence')

    def test_both_sdks_can_be_needed_and_rechecked(self):
        calls = self.run_prepare([1, 2, DISK.MINIMUM_FREE_BYTES], self.remove)
        self.assertEqual(len(calls), 2)
        self.assertTrue(self.sentinel.exists())

    def test_persistently_low_capacity_fails_without_sweeping_other_paths(self):
        with self.assertRaisesRegex(RuntimeError, 'Insufficient'):
            self.run_prepare([1, 2, 3], self.remove)
        self.assertTrue(self.sentinel.exists())

    def test_non_hosted_or_non_linux_environments_never_cleanup(self):
        for key, value in [('GITHUB_ACTIONS', 'false'), ('RUNNER_ENVIRONMENT', 'self-hosted'), ('RUNNER_OS', 'Windows')]:
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'disposable'):
                self.run_prepare([1], self.remove, dict(self.environment, **{key: value}))
        self.assertTrue(all(directory.exists() for directory in self.sdks))

    def test_symlink_and_mount_boundaries_are_refused(self):
        shutil.rmtree(self.sdks[0])
        self.sdks[0].symlink_to(self.workspace, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'boundary'):
            self.run_prepare([1], self.remove)
        self.sdks[0].unlink()
        self.sdks[0].mkdir()
        with patch.object(Path, 'is_mount', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'boundary'):
                self.run_prepare([1], self.remove)
        self.assertTrue(self.sentinel.exists())

    def test_other_filesystem_is_refused(self):
        actual_stat = Path.stat

        def different_device(path, *args, **kwargs):
            result = actual_stat(path, *args, **kwargs)
            if path == self.sdks[0]:
                fields = list(result)
                fields[2] += 1
                return os.stat_result(fields)
            return result

        with patch.object(Path, 'stat', different_device):
            with self.assertRaisesRegex(RuntimeError, 'boundary'):
                self.run_prepare([1], self.remove)
        self.assertTrue(self.sdks[0].exists())

    def test_missing_sdks_do_not_expand_cleanup_scope(self):
        for directory in self.sdks:
            shutil.rmtree(directory)
        with self.assertRaisesRegex(RuntimeError, 'Insufficient'):
            self.run_prepare([1], self.remove)
        self.assertTrue(self.sentinel.exists())

    def test_delete_failure_is_not_ignored(self):
        def failed_delete(*args, **kwargs):
            raise subprocess.CalledProcessError(1, 'fixture')

        with self.assertRaises(subprocess.CalledProcessError):
            self.run_prepare([1], failed_delete)
        self.assertTrue(self.sentinel.exists())


if __name__ == '__main__':
    unittest.main()
