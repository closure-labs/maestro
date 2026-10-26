# SPDX-License-Identifier: Apache-2.0
"""Race claimed mount names as XO while the real privileged wrapper mounts NFS."""
import errno
import os
from pathlib import Path
import pwd
import subprocess
import sys


wrapper = sys.argv[1]
target = Path('/var/lib/xo/mounts/nfs')
original = target.stat()
account = pwd.getpwnam('xo')
read_fd, write_fd = os.pipe()
child = os.fork()
if child == 0:
    os.close(write_fd)
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    os.read(read_fd, 1)
    for _ in range(2000):
        for source, destination in [(target, target.with_name('race-replaced')),
                                    (target.parent, target.parent.with_name('race-root'))]:
            try:
                os.rename(source, destination)
            except OSError as error:
                if error.errno not in (errno.EPERM, errno.EACCES, errno.EBUSY):
                    os._exit(2)
            else:
                os._exit(3)
        try:
            os.symlink('/etc', target)
        except FileExistsError:
            pass
        else:
            os._exit(4)
    os._exit(0)
os.close(read_fd)
os.write(write_fd, b'1')
os.close(write_fd)
try:
    invoke = ['runuser', '-u', 'xo', '--', wrapper]
    for _ in range(5):
        subprocess.run(invoke + ['mount', '-t', 'nfs', '-o', 'vers=4', 'storage:/srv/fixture', str(target)], check=True)
        subprocess.run(['runuser', '-u', 'xo', '--', 'cat', str(target / 'roundtrip')], check=True)
        subprocess.run(invoke + ['umount', str(target)], check=True)
finally:
    _, status = os.waitpid(child, 0)
assert os.waitstatus_to_exitcode(status) == 0, 'XO replaced a claimed pathname during mounting'
current = target.stat()
assert (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino)
assert not target.is_symlink()
print('Concurrent mount-name replacement remained contained')
