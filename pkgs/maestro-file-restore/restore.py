"""XO file restore protocol v1. Guest paths are interpreted only by guestfs RPC."""

import ctypes
import json
import os
import resource
import signal
import stat
import sys
import tarfile
import threading
import zipfile
from contextlib import contextmanager

FILESYSTEMS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "ntfs", "ntfs3"}
MAX_ENTRIES = 10000


def guest_path(value):
    if not isinstance(value, str) or any(char in value for char in ("\0", "\\", ":")):
        raise ValueError("invalid guest path")
    parts = value.split("/")
    if ".." in parts:
        raise ValueError("parent traversal is forbidden")
    return "/" + "/".join(part for part in parts if part not in {"", "."})


def entry_name(value):
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ValueError("invalid guest directory entry")
    if any(char in value for char in ("/", "\\", "\0", ":")):
        raise ValueError("unsafe archive entry")
    return value


def checked_stat(handle, path):
    """Refuse symlinks in every requested ancestor, including download roots."""
    current = ""
    result = handle.lstatns("/")
    for part in path.split("/")[1:]:
        if not part:
            continue
        current += "/" + part
        result = handle.lstatns(current)
        if stat.S_ISLNK(result["st_mode"]):
            raise ValueError("symbolic links are not restored")
    return result


def partitions(handle):
    return [
        {"id": device, "name": device.removeprefix("/dev/") + " (" + filesystem + ")",
         "size": handle.blockdev_getsize64(device)}
        for device, filesystem in sorted(handle.list_filesystems().items())
        if filesystem in FILESYSTEMS
    ]


def mount_partition(handle, partition):
    filesystems = handle.list_filesystems()
    if partition is None:
        devices = handle.list_devices()
        if len(devices) != 1 or devices[0] not in filesystems:
            raise ValueError("select a partition from listPartitions first")
        partition = devices[0]
    filesystem = filesystems.get(partition)
    if filesystem not in FILESYSTEMS:
        raise ValueError("partition is not a supported filesystem on this disk")
    # Never replay guest journals; failures remain failures rather than dropping
    # these options. The raw backing image also remains read-only in QEMU.
    options = "ro"
    if filesystem in {"ext3", "ext4"}:
        options += ",noload"
    elif filesystem == "xfs":
        options += ",norecovery"
    handle.mount_vfs(options, filesystem, partition, "/")


def list_files(handle, path):
    if not stat.S_ISDIR(checked_stat(handle, path)["st_mode"]):
        raise ValueError("requested path is not a directory")
    entries = handle.readdir(path)
    if len(entries) > MAX_ENTRIES:
        raise ValueError("directory exceeds restore entry limit")
    result = {}
    for entry in entries:
        if entry["name"] in {".", ".."}:
            continue
        name = entry_name(entry["name"])
        mode = handle.lstatns(path.rstrip("/") + "/" + name)["st_mode"]
        if stat.S_ISDIR(mode):
            result[name + "/"] = {}
        elif stat.S_ISREG(mode):
            result[name] = {}
    return result


def walk(handle, paths):
    seen = set()
    pending = [(guest_path(path), 0) for path in reversed(paths)]
    while pending:
        path, depth = pending.pop()
        if path in seen:
            continue
        if len(seen) >= MAX_ENTRIES or depth > 128:
            raise ValueError("archive exceeds restore entry/depth limit")
        seen.add(path)
        info = checked_stat(handle, path)
        mode = info["st_mode"]
        if stat.S_ISDIR(mode):
            entries = handle.readdir(path)
            if len(entries) > MAX_ENTRIES:
                raise ValueError("directory exceeds restore entry limit")
            for entry in reversed(entries):
                if entry["name"] not in {".", ".."}:
                    name = entry_name(entry["name"])
                    child = path.rstrip("/") + "/" + name
                    # Archive traversal skips links and special devices; no host
                    # paths, guest executable, sockets or FIFOs are opened.
                    child_mode = handle.lstatns(child)["st_mode"]
                    if stat.S_ISDIR(child_mode) or stat.S_ISREG(child_mode):
                        pending.append((child, depth + 1))
        elif not stat.S_ISREG(mode):
            raise ValueError("only regular files and directories can be restored")
        yield path, info


@contextmanager
def download(handle, path):
    read_fd, write_fd = os.pipe()
    errors = []

    def transfer():
        try:
            # The local output is a pipe created here, never a guest filename.
            handle.download(path, "/proc/self/fd/" + str(write_fd))
        except BaseException as error:
            errors.append(error)
        finally:
            os.close(write_fd)

    worker = threading.Thread(target=transfer, daemon=True)
    with os.fdopen(read_fd, "rb") as stream:
        worker.start()
        try:
            yield stream
        finally:
            # Closing first also wakes a blocked producer when the client aborts.
            stream.close()
            worker.join()
    if errors:
        raise errors[0]


def archive(handle, paths, format, output):
    if format not in {"tgz", "zip"}:
        raise ValueError("unsupported archive format")
    if not isinstance(paths, list) or not paths or len(paths) > 1024:
        raise ValueError("invalid archive selection")
    if format == "tgz":
        with tarfile.open(fileobj=output, mode="w|gz", format=tarfile.PAX_FORMAT) as pack:
            for path, info in walk(handle, paths):
                name = path.lstrip("/") or "."
                item = tarfile.TarInfo(name)
                item.mode = info["st_mode"] & 0o777
                item.mtime = info["st_mtime_sec"]
                if stat.S_ISDIR(info["st_mode"]):
                    item.type = tarfile.DIRTYPE
                    pack.addfile(item)
                else:
                    item.size = info["st_size"]
                    with download(handle, path) as stream:
                        pack.addfile(item, stream)
    else:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as pack:
            for path, info in walk(handle, paths):
                name = path.lstrip("/") or "."
                directory = stat.S_ISDIR(info["st_mode"])
                item = zipfile.ZipInfo(name + "/" if directory else name)
                item.external_attr = (info["st_mode"] & ~0o7000) << 16
                item.compress_type = zipfile.ZIP_DEFLATED
                if directory:
                    pack.writestr(item, b"")
                else:
                    with download(handle, path) as source, pack.open(item, "w", force_zip64=True) as target:
                        while chunk := source.read(1024 * 1024):
                            target.write(chunk)


def run(request, handle, output):
    if request.get("version") != 1 or request.get("operation") not in {"partitions", "files", "archive"}:
        raise ValueError("unsupported file restore request")
    operation = request["operation"]
    if operation == "partitions":
        output.write(json.dumps(partitions(handle)).encode() + b"\n")
        return
    mount_partition(handle, request.get("partition"))
    if operation == "files":
        output.write(json.dumps(list_files(handle, guest_path(request.get("path", "/")))).encode() + b"\n")
    else:
        archive(handle, request.get("paths"), request.get("format"), output)


def main():
    if os.geteuid() == 0:
        raise ValueError("file restore must run as the unprivileged XO account")
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "cannot restrict restore privileges")
    # TCG reserves executable address space in addition to the 512 MiB RAM;
    # this is a virtual-address ceiling, not the guest's memory allocation.
    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (840, 840))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError("restore request exceeds limit")
    request = json.loads(raw)
    disk = request.get("disk")
    if not isinstance(disk, str) or not os.path.isabs(disk) or not stat.S_ISREG(os.stat(disk).st_mode):
        raise ValueError("restore disk must be an absolute regular raw-image path")
    import guestfs

    handle = guestfs.GuestFS(python_return_dict=True)
    def terminate(_signal, _frame):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, terminate)
    try:
        handle.set_backend("direct")
        handle.set_network(False)
        handle.set_memsize(512)
        handle.set_smp(1)
        handle.add_drive_opts(disk, format="raw", readonly=True)
        handle.launch()
        run(request, handle, sys.stdout.buffer)
    finally:
        handle.close()


if __name__ == "__main__":
    try:
        main()
    except (Exception, BrokenPipeError) as error:
        print("file restore failed: " + str(error), file=sys.stderr)
        sys.exit(1)
