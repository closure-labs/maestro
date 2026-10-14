"""Real raw/partition/LVM images, with no host filesystem mounts."""
import hashlib
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time
import zipfile

import guestfs

helper, directory = sys.argv[1:]
assert os.geteuid() != 0
directory = Path(directory)
directory.mkdir()
images = [directory / name for name in ("raw.img", "partition.img", "lvm.img")]
for image in images:
    with image.open("wb") as output:
        output.truncate(128 * 1024**2)

handle = guestfs.GuestFS(python_return_dict=True)
handle.set_network(False)
handle.set_memsize(512)
handle.set_smp(1)
handle.set_append("maestro_restore_root=/dev/sdd")
handle.config("-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny")
for image in images:
    handle.add_drive_opts(str(image), format="raw")
try:
    handle.launch()
    devices = handle.list_devices()
    handle.mkfs("ext4", devices[0])
    handle.part_disk(devices[1], "mbr")
    handle.mkfs("ext4", devices[1] + "1")
    handle.part_disk(devices[2], "mbr")
    handle.pvcreate(devices[2] + "1")
    handle.vgcreate("restore_fixture", [devices[2] + "1"])
    handle.lvcreate("data", "restore_fixture", 64)
    handle.mkfs("ext4", "/dev/restore_fixture/data")
    for device in (devices[0], devices[1] + "1", "/dev/restore_fixture/data"):
        handle.mount(device, "/")
        handle.mkdir("/docs")
        handle.write("/docs/sentinel", b"isolated restore data\n")
        handle.ln_s("/etc/shadow", "/escape")
        handle.umount_all()
finally:
    handle.close()


def invoke(operation, image, **options):
    request = {"version": 1, "operation": operation, "disk": str(image), **options}
    return subprocess.run([helper], input=json.dumps(request).encode(), capture_output=True, timeout=240)


before_mounts = Path("/proc/self/mountinfo").read_text()
before_loops = sorted(Path("/sys/block").glob("loop*"))

# Serialize actual appliance work and release the lock after cancellation.
request = {"version": 1, "operation": "partitions", "disk": str(images[0])}
process = subprocess.Popen([helper], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
process.stdin.write(json.dumps(request).encode())
process.stdin.close()
lock = Path(os.environ["TMPDIR"]) / "maestro-file-restore.lock"
try:
    held = False
    for attempt in range(200):
        if lock.exists():
            with lock.open("rb") as descriptor:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    held = True
        if held:
            break
        assert process.poll() is None, "restore exited before acquiring its lock"
        time.sleep(0.01)
    assert held, "restore lock was not held"
    result = invoke("partitions", images[0])
    assert result.returncode == 75 and b"busy" in result.stderr
finally:
    process.terminate()
    process.wait(timeout=30)
    process.stdout.close()
    process.stderr.close()
with lock.open("rb") as descriptor:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

for image in images:
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    result = invoke("partitions", image)
    assert result.returncode == 0, result.stderr.decode()
    partitions = json.loads(result.stdout)
    assert len(partitions) == 1, partitions
    partition = partitions[0]["id"]
    result = invoke("files", image, partition=partition, path="/docs")
    assert result.returncode == 0, result.stderr.decode()
    assert json.loads(result.stdout) == {"sentinel": {}}
    for format in ("tgz", "zip"):
        result = invoke("archive", image, partition=partition, paths=["/docs"], format=format)
        assert result.returncode == 0, result.stderr.decode()
        data = io.BytesIO(result.stdout)
        if format == "tgz":
            with tarfile.open(fileobj=data) as archive:
                assert archive.extractfile("docs/sentinel").read() == b"isolated restore data\n"
        else:
            with zipfile.ZipFile(data) as archive:
                assert archive.read("docs/sentinel") == b"isolated restore data\n"
    assert invoke("files", image, partition=partition, path="/escape").returncode != 0
    assert invoke("files", image, partition=partition, path="/../../etc").returncode != 0
    assert hashlib.sha256(image.read_bytes()).hexdigest() == before, "backup disk modified"

assert Path("/proc/self/mountinfo").read_text() == before_mounts
assert sorted(Path("/sys/block").glob("loop*")) == before_loops
invalid = directory / "invalid.img"
invalid.write_bytes(b"not a filesystem" * 4096)
result = invoke("partitions", invalid)
assert result.returncode != 0 or json.loads(result.stdout) == []
print("real raw, partition, LVM, archive, read-only and host mount isolation acceptance passed")
