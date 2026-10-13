#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Claim mount directories beneath a protected root before privileged tools run.

Each ancestor is opened without following symlinks. Root ownership and sticky
directories prevent XO from replacing the pathname after validation, including
when a downstream mount/FUSE utility canonicalizes a /proc/self/fd path.
"""
import os
from pathlib import PurePosixPath
import stat
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def protected(fd):
    info = os.fstat(fd)
    require(info.st_uid == 0, "mount ancestor must be root-owned")
    require(not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX, "writable mount ancestor must be sticky")


def claim(root, target, group):
    require(os.geteuid() == 0, "mount guard requires root")
    require(root.startswith("/") and target.startswith("/"), "mount paths must be absolute")
    require(".." not in target.split("/") and ".." not in root.split("/"), "parent traversal is forbidden")
    root_parts, target_parts = PurePosixPath(root).parts[1:], PurePosixPath(target).parts[1:]
    require(target_parts[:len(root_parts)] == root_parts and len(target_parts) > len(root_parts), "target must be below the mount root")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(target_parts):
            protected(fd)
            parent_info = os.fstat(fd)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                info = os.fstat(child)
                in_root = index >= len(root_parts)
                if in_root:
                    # An existing mount is allowed only as the final component;
                    # remote servers cannot provide trusted path ancestors.
                    if info.st_dev != parent_info.st_dev:
                        require(index == len(target_parts) - 1, "mount target crosses a remote filesystem")
                    else:
                        os.fchown(child, 0, group)
                        os.fchmod(child, 0o1770)
                else:
                    protected(child)
                current = os.stat(part, dir_fd=fd, follow_symlinks=False)
                require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), "mount directory changed while being claimed")
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        claim(os.environ["MAESTRO_XO_MOUNTS_DIR"], sys.argv[1], int(sys.argv[2]))
    except (ValueError, OSError, KeyError, IndexError) as error:
        print(f"xo-mount-guard: {error}", file=sys.stderr)
        sys.exit(1)
