# SPDX-License-Identifier: Apache-2.0
"""Atomic job-local storage of authenticated metadata bytes, never authority."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat

import operations


class MetadataCache:
    def __init__(self, directory):
        self.directory = Path(directory)
        if not self.directory.is_absolute() or '..' in self.directory.parts:
            raise ValueError('Unsafe packet metadata cache path')

    @contextmanager
    def opened(self, create=False):
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in self.directory.parts[1:]:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                except FileNotFoundError:
                    if create:
                        raise ValueError('Packet metadata cache disappeared')
                    yield None
                    return
                os.close(descriptor)
                descriptor = child
            yield descriptor
        except OSError as error:
            raise ValueError('Unsafe packet metadata cache path or member') from error
        finally:
            os.close(descriptor)

    @staticmethod
    def read_at(directory, digest, limit, size=None):
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Invalid packet metadata cache identity')
        operations.remaining(90)
        try:
            descriptor = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_size > limit
                    or (size is not None and info.st_size != size)):
                raise ValueError('Invalid packet metadata cache type or size')
            raw = stream.read(limit + 1)
        if (len(raw) > limit or (size is not None and len(raw) != size)
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('Packet metadata cache integrity failure')
        operations.remaining(90)
        return raw

    def read(self, digest, limit, size=None):
        with self.opened() as directory:
            return None if directory is None else self.read_at(directory, digest, limit, size)

    def store(self, digest, raw):
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Packet metadata cache integrity failure')
        with self.opened(create=True) as directory:
            name = '.metadata-' + os.urandom(16).hex()
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 mode=0o600, dir_fd=directory)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(raw)
                operations.remaining(90)
                try:
                    os.link(name, digest, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                except FileExistsError:
                    if self.read_at(directory, digest, len(raw), len(raw)) != raw:
                        raise ValueError('Conflicting packet metadata cache binding')
            finally:
                os.unlink(name, dir_fd=directory)
