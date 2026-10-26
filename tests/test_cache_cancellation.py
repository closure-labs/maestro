# SPDX-License-Identifier: Apache-2.0
"""Interrupting parallel metadata reads cleans every detached transport."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'modules/ci/authority/_source/decisions'
sys.path.insert(0, str(CORE))
import operations


class CacheCancellation(unittest.TestCase):
    def test_sigterm_cleans_parallel_curls_and_detached_descendants(self):
        with tempfile.TemporaryDirectory(prefix='cache-cancellation-') as temporary:
            directory = Path(temporary)
            binaries, pids = directory / 'bin', directory / 'pids'
            binaries.mkdir()
            pids.mkdir()
            detached = ('import os,signal,time; from pathlib import Path; '
                        'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                        f'Path({str(pids)!r},str(os.getpid())).write_text("ready"); time.sleep(30)')
            curl = binaries / 'curl'
            curl.write_text('#!' + sys.executable + '\n'
                            'import os,signal,subprocess,sys,time\nfrom pathlib import Path\n'
                            'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                            f'subprocess.Popen([sys.executable,"-c",{detached!r}],start_new_session=True)\n'
                            f'Path({str(pids)!r},str(os.getpid())).write_text("ready")\n'
                            'time.sleep(30)\n')
            curl.chmod(0o700)
            product = {'products': {str(number): {
                'storePath': '/nix/store/' + str(number) * 32 + '-fixture',
                'narHash': 'sha256-' + 'A' * 43 + '='} for number in range(2)}}
            helper = ('import sys; '
                      f'sys.path.insert(0,{str(CORE)!r}); '
                      'import destinations,operations; operations.KILL_GRACE=.05; '
                      f'destinations.cache({product!r},"https://maestro.cachix.org")')
            environment = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'])
            child = subprocess.Popen([sys.executable, '-c', helper], env=environment,
                                     start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            identities = {}
            try:
                ready_deadline = time.monotonic() + 5
                while len(list(pids.iterdir())) < 4 and time.monotonic() < ready_deadline:
                    if child.poll() is not None:
                        break
                    time.sleep(.01)
                self.assertEqual(len(list(pids.iterdir())), 4, 'parallel transports were not ready')
                identities = {int(path.name): operations.process_identity(int(path.name))
                              for path in pids.iterdir()}
                started = time.monotonic()
                child.send_signal(signal.SIGTERM)
                child.communicate(timeout=3)
                self.assertEqual(child.returncode, 143)
                observation_deadline = time.monotonic() + .5
                while True:
                    surviving = []
                    for pid in identities:
                        try:
                            state = Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[0]
                        except OSError:
                            state = None
                        if state not in (None, 'Z'):
                            surviving.append(pid)
                    if not surviving or time.monotonic() >= observation_deadline:
                        break
                    time.sleep(.01)
                self.assertEqual(surviving, [], 'metadata transports survived SIGTERM cleanup')
                self.assertLess(time.monotonic() - started, 2)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.communicate()
                # Also clean deliberately surviving fixtures when this test
                # detects a regression in the production cancellation guard.
                for path in pids.iterdir():
                    pid = int(path.name)
                    previous = identities.get(pid)
                    current = operations.process_identity(pid)
                    if current is not None and (previous is None or current[1] == previous[1]):
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == '__main__':
    unittest.main()
