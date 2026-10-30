#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reserve disk on disposable hosted runners without touching Nix or evidence."""
import os
from pathlib import Path
import shutil
import subprocess

MINIMUM_FREE_BYTES = 20 * 1024 ** 3
# These host SDKs are unused: Maestro resolves its tools through pinned Nix.
# Never accept cleanup paths from workflow inputs, the environment or arguments.
UNUSED_SDKS = (Path('/usr/local/lib/android'), Path('/usr/share/dotnet'))


def prepare():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('RUNNER_OS') != 'Linux'):
        raise RuntimeError('Disk preparation requires a disposable GitHub-hosted Linux runner')
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    device = workspace.stat().st_dev

    def available():
        free = shutil.disk_usage(workspace).free
        print(f'Runner disk: {free} bytes available; require {MINIMUM_FREE_BYTES}', flush=True)
        return free

    if available() >= MINIMUM_FREE_BYTES:
        return
    for directory in UNUSED_SDKS:
        if not directory.exists():
            continue
        if (directory.is_symlink() or not directory.is_dir()
                or directory.resolve(strict=True) != directory
                or directory.is_mount() or directory.stat().st_dev != device):
            raise RuntimeError(f'Unexpected SDK cleanup boundary: {directory}')
        print(f'Reclaiming unused hosted SDK only: {directory}', flush=True)
        subprocess.run(['sudo', '-n', 'rm', '-rf', '--one-file-system', '--', str(directory)], check=True)
        if available() >= MINIMUM_FREE_BYTES:
            return
    raise RuntimeError('Insufficient hosted runner disk after bounded SDK reclamation; require 20 GiB before Nix')


if __name__ == '__main__':
    prepare()
