"""Semantic RPC/archive checks; actual guest-kernel fixtures run on GitHub."""
import importlib.util
import io
import os
from pathlib import Path
import stat
import tarfile
import zipfile

spec = importlib.util.spec_from_file_location("restore", Path(__file__).parents[1] / "modules/features/xo/file-restore/_source/restore.py")
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


class Guest:
    files = {"/docs/hello": b"guest data", "/empty": b""}
    dirs = {"/": ["docs", "empty", "escape", "device"], "/docs": ["hello"]}

    def lstatns(self, path):
        mode = stat.S_IFDIR if path in self.dirs else stat.S_IFREG
        if path == "/escape":
            mode = stat.S_IFLNK
        elif path == "/device":
            mode = stat.S_IFBLK
        elif path not in self.dirs and path not in self.files:
            raise FileNotFoundError(path)
        return {"st_mode": mode | 0o755, "st_size": len(self.files.get(path, b"")), "st_mtime_sec": 1}

    def readdir(self, path):
        return [{"name": name} for name in [".", ".."] + self.dirs[path]]

    def download(self, path, output):
        with open(output, "wb") as stream:
            stream.write(self.files[path])

    def list_filesystems(self):
        return {"/dev/sda1": "ext4", "/dev/vg/data": "xfs", "/dev/sda2": "swap"}

    def list_devices(self):
        return ["/dev/sda"]

    def blockdev_getsize64(self, device):
        return 1048576

    def mount_vfs(self, options, fs, partition, path):
        self.mounted = (options, fs, partition, path)


def rejected(function, *args):
    try:
        function(*args)
    except (ValueError, FileNotFoundError):
        return
    raise AssertionError("unsafe input accepted")


guest = Guest()
assert restore.guest_path("/docs/./hello") == "/docs/hello"
for path in ["../secret", "/docs/../../secret", "C:/host", "back\\slash", "bad\0name"]:
    rejected(restore.guest_path, path)
assert restore.list_files(guest, "/") == {"docs/": {}, "empty": {}}
rejected(restore.checked_stat, guest, "/escape/secret")
rejected(restore.mount_partition, guest, "/dev/host/root")
rejected(restore.mount_partition, guest, None)
assert [entry["id"] for entry in restore.partitions(guest)] == ["/dev/sda1", "/dev/vg/data"]
restore.mount_partition(guest, "/dev/sda1")
assert guest.mounted == ("ro,noload", "ext4", "/dev/sda1", "/")
restore.mount_partition(guest, "/dev/vg/data")
assert guest.mounted[0] == "ro,norecovery"

for format in ["tgz", "zip"]:
    output = io.BytesIO()
    restore.archive(guest, ["/"], format, output)
    output.seek(0)
    if format == "tgz":
        with tarfile.open(fileobj=output) as pack:
            assert set(pack.getnames()) == {".", "docs", "docs/hello", "empty"}
            assert pack.extractfile("docs/hello").read() == b"guest data"
    else:
        with zipfile.ZipFile(output) as pack:
            assert set(pack.namelist()) == {"./", "docs/", "docs/hello", "empty"}
            assert pack.read("docs/hello") == b"guest data"
    rejected(restore.archive, guest, ["/escape"], format, io.BytesIO())
    rejected(restore.archive, guest, ["/device"], format, io.BytesIO())

restore.MAX_ENTRIES = 2
rejected(lambda: list(restore.walk(guest, ["/"])))
assert not any(thread.name != "MainThread" for thread in restore.threading.enumerate())
print("file restore RPC and archive boundary fixtures passed")
