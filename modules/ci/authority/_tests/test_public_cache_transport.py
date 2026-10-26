# SPDX-License-Identifier: Apache-2.0
"""Real pinned TLS readers, shared retries, traversal and process cleanup."""
import http.server
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
CORE = ROOT / 'modules/ci/authority/_source/decisions'
sys.path.insert(0, str(CORE))
import destinations
import diagnostics
import diagnostic_requests
import operations
import public_cache_transport as transport

LIBRARY = os.environ['MAESTRO_TEST_LIBCURL']
CURL = os.environ['MAESTRO_TEST_CURL']
OPENSSL = os.environ.get('MAESTRO_TEST_OPENSSL', 'openssl')
HASH = 'sha256-' + 'A' * 43 + '='


def path(number):
    return '/nix/store/' + format(number, '032x') + '-fixture'


def url(number, host='maestro.cachix.org'):
    return 'https://' + host + '/' + format(number, '032x') + '.narinfo'


def metadata(number, references=()):
    return (f'StorePath: {path(number)}\nURL: nar/fixture.nar\nNarHash: {HASH}\nNarSize: 1\n'
            + 'References: ' + ' '.join(Path(path(n)).name for n in references) + '\n').encode()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.routes = {}
        self.requests = {}
        self.lock = threading.Lock()
        self.accepted = self.active = self.maximum = 0

    def get_request(self):
        value = super().get_request()
        with self.lock:
            self.accepted += 1
        return value


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (ConnectionError, ssl.SSLError):
            pass

    def do_GET(self):
        key = (self.headers['Host'], self.path)
        with self.server.lock:
            count = self.server.requests[key] = self.server.requests.get(key, 0) + 1
            self.server.active += 1
            self.server.maximum = max(self.server.maximum, self.server.active)
        try:
            route = self.server.routes.get(key, (404, b'missing', {}))
            if callable(route):
                route = route(count)
            if route is None:
                self.close_connection = True
                return
            code, body, headers = route
            self.send_response(code)
            if 'Transfer-Encoding' not in headers:
                self.send_header('Content-Length', str(len(body)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            if headers.get('Transfer-Encoding') == 'chunked':
                for offset in range(0, len(body), 65536):
                    chunk = body[offset:offset+65536]
                    self.wfile.write(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                self.wfile.write(b'0\r\n\r\n')
            else:
                self.wfile.write(body)
            self.wfile.flush()
        except (ConnectionError, ssl.SSLError):
            self.close_connection = True
        finally:
            with self.server.lock:
                self.server.active -= 1


class Proxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class H2Handler(socketserver.BaseRequestHandler):
    def read(self, size):
        data = b''
        while len(data) < size:
            chunk = self.request.recv(size - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def frame(self, kind, flags, stream, body=b''):
        self.request.sendall(len(body).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + body)

    def handle(self):
        self.request.settimeout(3)
        try:
            assert self.read(24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
            self.frame(4, 0, 0)
            while True:
                head = self.read(9)
                length, kind, flags = int.from_bytes(head[:3], 'big'), head[3], head[4]
                stream = int.from_bytes(head[5:], 'big') & 0x7fffffff
                body = self.read(length)
                if kind == 4 and not flags & 1:
                    self.frame(4, 1, 0)
                if kind == 6 and not flags & 1:
                    self.frame(6, 1, 0, body)
                if kind == 1:
                    assert flags & 4
                    with self.server.lock:
                        self.server.h2requests += 1
                        number = self.server.h2requests
                    if number in self.server.refused:
                        self.frame(3, 0, stream, (7).to_bytes(4, 'big'))
                    else:
                        self.frame(1, 4, stream, b'\x88')
                        self.frame(0, 1, stream, b'HTTP2 metadata')
        except (EOFError, ConnectionError, ssl.SSLError, TimeoutError):
            pass


class Tunnel(socketserver.BaseRequestHandler):
    def handle(self):
        peer = None
        try:
            self.request.settimeout(2)
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = self.request.recv(1024)
                if not chunk or len(data) + len(chunk) > 4096:
                    return
                data += chunk
            if not data.startswith(b'CONNECT '):
                return
            peer = socket.create_connection(self.server.target, timeout=2)
            self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            while True:
                ready, _, _ = select.select([self.request, peer], [], [], .1)
                for source in ready:
                    block = source.recv(65536)
                    if not block:
                        return
                    (peer if source is self.request else self.request).sendall(block)
        except (OSError, TimeoutError):
            pass
        finally:
            if peer:
                peer.close()


class PublicTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='public-transport-')
        cls.directory = Path(cls.temp.name)
        cls.cert = cls.directory / 'cert.pem'
        subprocess.run([OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=maestro.cachix.org', '-addext',
                        'subjectAltName=DNS:maestro.cachix.org,DNS:cache.nixos.org,DNS:xen-orchestra-ce.cachix.org',
                        '-keyout', str(cls.directory/'key.pem'), '-out', str(cls.cert)],
                       capture_output=True, check=True, timeout=10)
        cls.worker = cls.directory / 'worker.py'
        cls.worker.write_text((CORE/'public_cache_worker.py').read_text().replace('@LIBCURL@', LIBRARY))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.server = Server(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(self.cert, self.directory/'key.pem')
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.proxy = Proxy(('127.0.0.1', 0), Tunnel)
        self.proxy.target = self.server.server_address
        self.threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (self.server, self.proxy)]
        for thread in self.threads:
            thread.start()
        proxy = f'http://127.0.0.1:{self.proxy.server_address[1]}'
        environment = {key: value for key, value in os.environ.items() if 'proxy' not in key.lower()}
        environment.update(https_proxy=proxy, HTTPS_PROXY=proxy, no_proxy='', NO_PROXY='',
                           SSL_CERT_FILE=str(self.cert), CURL_CA_BUNDLE=str(self.cert),
                           PUBLICATION_CURL_WORKER_SOURCE=str(self.worker),
                           MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED='true', MAESTRO_CI_DIAGNOSTICS='false')
        environment['PATH'] = str(Path(CURL).parent) + os.pathsep + environment['PATH']
        self.environment = patch.dict(os.environ, environment, clear=True)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        for server in (self.server, self.proxy):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)

    def route(self, number, body=None, status=200, headers=None, host='maestro.cachix.org', callback=None):
        key = (host, '/' + format(number, '032x') + '.narinfo')
        self.server.routes[key] = callback or (status, metadata(number) if body is None else body, headers or {})
        return key

    def test_reuse_bytes_and_mutation_are_fresh(self):
        key = self.route(1)
        with transport.Reader(8) as read:
            first = read(url(1))
            connections = self.server.accepted
            self.assertEqual(first, destinations.http(url(1)))
            for _ in range(3):
                self.assertEqual(read(url(1)), first)
            self.assertEqual(self.server.accepted, connections + 1)  # one legacy process
            self.route(1, body=b'changed')
            self.assertEqual(read(url(1)), (200, b'changed'))
            children = list(read.children.values())
        self.assertTrue(all(c.poll() is not None for c in children))
        self.assertEqual(self.server.requests[key], 6)

    def test_disconnect_and_transient_retry_share_budget(self):
        self.route(1)
        drop = self.route(2, callback=lambda n: None if n == 1 else (200, b'recovered', {}))
        retry = self.route(3, callback=lambda n: (503, b'transient', {}) if n == 1 else (200, b'recovered', {}))
        mixed = self.route(4, callback=lambda n: None if n == 1 else (503, b'stop', {}))
        forever = self.route(5, callback=lambda n: None)
        with transport.Reader(8) as read:
            self.assertEqual(read(url(1))[0], 200)
            self.assertEqual(read(url(2)), (200, b'recovered'))
            self.assertEqual(read(url(3)), (200, b'recovered'))
            self.assertEqual(read(url(4)), (503, b'stop'))
            self.assertEqual(read(url(5)), (None, b''))
        for key in (drop, retry, mixed, forever):
            self.assertEqual(self.server.requests[key], 2)

    def test_retry_after_does_not_exceed_window(self):
        key = self.route(1, status=429, headers={'Retry-After': '60'})
        started = time.monotonic()
        with transport.Reader(8) as read:
            self.assertEqual(read(url(1))[0], 429)
        self.assertEqual(self.server.requests[key], 1)
        self.assertLess(time.monotonic() - started, 2)

    def test_retry_after_is_honored_when_it_fits(self):
        key = self.route(1, callback=lambda n: (429, b'wait', {'Retry-After': '2'}) if n == 1 else (200, b'ready', {}))
        started = time.monotonic()
        with transport.Reader(8) as read:
            self.assertEqual(read(url(1)), (200, b'ready'))
        self.assertEqual(self.server.requests[key], 2)
        self.assertGreaterEqual(time.monotonic() - started, 1.9)

    def test_http2_refused_stream_recovers_but_cannot_send_third_request(self):
        self.server.RequestHandlerClass = H2Handler
        self.server.socket.context.set_alpn_protocols(['h2'])
        for refused, expected in (({2}, 200), ({2, 3, 4}, None)):
            with self.subTest(refused=refused):
                self.server.h2requests = 0
                self.server.refused = refused
                with transport.Reader(8) as read:
                    self.assertEqual(read(url(1)), (200, b'HTTP2 metadata'))
                    self.assertEqual(read(url(2))[0], expected)
                self.assertEqual(self.server.h2requests, 3)

    def test_concurrency_and_shared_closure_deduplication(self):
        for number in [*range(8), 16, 17]:
            def delayed(count, number=number):
                time.sleep(.05)
                return 200, metadata(number, (16, 17) if number < 8 else ()), {}
            self.route(number, callback=delayed)
        product = {'products': {str(n): {'storePath': path(n), 'narHash': HASH} for n in range(8)}}
        value = destinations.cache(product, 'https://maestro.cachix.org')
        self.assertEqual(value['status'], 'verified')
        self.assertEqual(value['closure']['inspectedPaths'], 10)
        self.assertEqual(sum(self.server.requests.values()), 10)
        self.assertLessEqual(self.server.maximum, 8)
        self.assertGreater(self.server.maximum, 1)
        self.assertLessEqual(self.server.accepted, 8)

    def test_worker_environment_does_not_inherit_authority_credentials(self):
        self.route(1)
        with patch.dict(os.environ, {'GH_TOKEN': 'fixture-github-secret', 'CACHIX_AUTH_TOKEN': 'fixture-cache-secret'}):
            with transport.Reader(8) as read:
                self.assertEqual(read(url(1))[0], 200)
                child = next(iter(read.children.values()))
                environment = Path(f'/proc/{child.pid}/environ').read_bytes()
                self.assertNotIn(b'GH_TOKEN=', environment)
                self.assertNotIn(b'CACHIX_AUTH_TOKEN=', environment)

    def test_redirect_and_missing_are_not_retried(self):
        redirect = self.route(1, status=302, headers={'Location': url(2)})
        missing = self.route(3, status=404)
        with transport.Reader(8) as read:
            self.assertEqual(read(url(1))[0], 302)
            self.assertEqual(read(url(3))[0], 404)
        self.assertEqual(self.server.requests, {redirect: 1, missing: 1})

    def test_content_length_and_chunked_bounds(self):
        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                self.route(1, body=b'x' * (transport.BODY_LIMIT + 1),
                           headers={'Transfer-Encoding': 'chunked'} if chunked else {})
                with transport.Reader(8) as read:
                    self.assertEqual(read(url(1)), (None, b''))

    def test_tls_failure_does_not_send_request(self):
        with patch.dict(os.environ, {'CURL_CA_BUNDLE': '/nonexistent-test-ca'}):
            with transport.Reader(8) as read:
                self.assertEqual(read(url(1)), (None, b''))
        self.assertEqual(self.server.requests, {})

    def test_origin_and_method_rejected_before_launch(self):
        with transport.Reader(8) as read:
            for address, head in [('https://evil.invalid/a', False), (url(1), True),
                                  (url(1)+'?token=secret', False), ('https://u:p@maestro.cachix.org/a', False)]:
                with self.subTest(address=address), self.assertRaises(ValueError):
                    read(address, head=head)
            self.assertEqual(read.children, {})

    def test_reader_deadline_rejects_late_response_and_cleans_inspection(self):
        def slow(count):
            time.sleep(.6)
            return 200, b'late', {}
        self.route(1, callback=slow)
        started = time.monotonic()
        with transport.Reader(8) as read:
            with operations.budget(.15):
                try:
                    value = read(url(1))
                except subprocess.TimeoutExpired:
                    pass
                else:
                    # libcurl's millisecond timeout can finish just before the
                    # supervisor's absolute deadline. Both reject the read.
                    self.assertEqual(value, (None, b''))
            children = list(read.children.values())
        self.assertTrue(children)
        self.assertTrue(all(c.poll() is not None for c in children))
        self.assertLess(time.monotonic() - started, 2)

    def test_supervisor_deadline_kills_unresponsive_worker_before_return(self):
        with tempfile.TemporaryDirectory() as temp:
            worker = Path(temp)/'unresponsive.py'
            worker.write_text('import sys,time\nsys.stdin.buffer.readline()\ntime.sleep(30)\n')
            with patch.dict(os.environ, {'PUBLICATION_CURL_WORKER_SOURCE': str(worker)}):
                started = time.monotonic()
                with transport.Reader(8) as read:
                    with operations.budget(.15), self.assertRaises(subprocess.TimeoutExpired):
                        read(url(1))
                    self.assertTrue(read.children)
                    self.assertTrue(all(c.poll() is not None for c in read.children.values()))
                self.assertLess(time.monotonic() - started, 2)

    def test_cache_parity_fallback_and_separate_inspections(self):
        self.route(1, body=metadata(1, (2,)))
        self.route(2, host='cache.nixos.org')
        product = {'products': {'root': {'storePath': path(1), 'narHash': HASH}}}
        args = (product, 'https://maestro.cachix.org')
        with patch.dict(os.environ, {transport.FLAG: 'false'}):
            old = destinations.cache(*args, upstreams=('https://cache.nixos.org',))
        current = destinations.cache(*args, upstreams=('https://cache.nixos.org',))
        self.assertEqual(current, old)
        self.assertEqual(current['status'], 'verified')
        self.assertEqual(current['closure']['inspectedPaths'], 2)
        self.route(1, body=metadata(1).replace(HASH.encode(), ('sha256-'+'B'*43+'=').encode()))
        self.assertEqual(destinations.cache(*args)['status'], 'conflict')

    def test_sigterm_cleans_workers_and_detached_descendants(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            pids = directory/'pids'
            pids.mkdir()
            detached = ('import os,signal,time;from pathlib import Path;'
                        'signal.signal(signal.SIGTERM,signal.SIG_IGN);'
                        f'Path({str(pids)!r},str(os.getpid())).write_text("ready");time.sleep(30)')
            worker = directory/'blocked.py'
            worker.write_text('import os,signal,subprocess,sys,time\nfrom pathlib import Path\n'
                              'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                              f'subprocess.Popen([sys.executable,"-c",{detached!r}],start_new_session=True)\n'
                              f'Path({str(pids)!r},str(os.getpid())).write_text("ready")\ntime.sleep(30)\n')
            product = {'products': {str(n): {'storePath': path(n), 'narHash': HASH} for n in range(2)}}
            helper = (f'import sys;sys.path.insert(0,{str(CORE)!r});'
                      'import destinations,operations;operations.KILL_GRACE=.05;'
                      f'destinations.cache({product!r},"https://maestro.cachix.org")')
            child = subprocess.Popen([sys.executable, '-c', helper],
                                     env=dict(os.environ, PUBLICATION_CURL_WORKER_SOURCE=str(worker)),
                                     start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            identities = {}
            try:
                deadline = time.monotonic() + 5
                while len(list(pids.iterdir())) < 4 and time.monotonic() < deadline and child.poll() is None:
                    time.sleep(.01)
                self.assertEqual(len(list(pids.iterdir())), 4)
                identities = {int(p.name): operations.process_identity(int(p.name)) for p in pids.iterdir()}
                child.send_signal(signal.SIGTERM)
                child.communicate(timeout=3)
                self.assertEqual(child.returncode, 143)
                for pid in identities:
                    status = Path(f'/proc/{pid}/stat')
                    self.assertTrue(not status.exists() or status.read_text().rpartition(')')[2].split()[0] == 'Z')
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.communicate()
                for pid, identity in identities.items():
                    current = operations.process_identity(pid)
                    if current and identity and current[1] == identity[1]:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_oversized_worker_frame_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            worker = Path(temp)/'oversized.py'
            worker.write_text(f'import sys,time\nsys.stdout.buffer.write(b"x"*{transport.REPLY_LIMIT+1})\nsys.stdout.flush()\ntime.sleep(30)\n')
            with patch.dict(os.environ, {'PUBLICATION_CURL_WORKER_SOURCE': str(worker)}):
                with transport.Reader(8) as read:
                    self.assertEqual(read(url(1)), (None, b''))
                    self.assertTrue(all(c.poll() is not None for c in read.children.values()))

    def test_malformed_metadata_and_worker_fail_closed(self):
        self.route(1, body=b'bad\n')
        product = {'products': {'root': {'storePath': path(1), 'narHash': HASH}}}
        with self.assertRaises(ValueError):
            destinations.cache(product, 'https://maestro.cachix.org')
        with patch.dict(os.environ, {'PUBLICATION_CURL_WORKER_SOURCE': '/missing-native-worker'}):
            self.assertEqual(destinations.cache(product, 'https://maestro.cachix.org')['status'], 'unavailable')

    def test_strict_flag_and_default_contract(self):
        for value in ('TRUE', '1', '', ' true'):
            with patch.dict(os.environ, {transport.FLAG: value}), self.assertRaises(ValueError):
                transport.enabled()
        with patch.dict(os.environ, {transport.FLAG: 'false'}):
            self.assertFalse(transport.enabled())
        contract = tomllib.loads((ROOT/'secretspec.toml').read_text())['profiles']['default'][transport.FLAG]
        self.assertEqual(contract['default'], 'false')
        self.assertFalse(contract['required'])

    def test_trial_requires_verified_destinations_and_preserves_gate_steps(self):
        workflow = json.loads(subprocess.check_output(
            ['yq', '-o=json', '.', str(ROOT/'.github/workflows/publication.yml')], text=True))
        trial = workflow['on']['workflow_dispatch']['inputs']['public_cache_transport_trial']
        self.assertEqual(trial['type'], 'boolean')
        self.assertIs(trial['default'], False)
        job = workflow['jobs']['publish']
        self.assertIn('inputs.public_cache_transport_trial', job['env'][transport.FLAG])
        self.assertIn('inputs.public_cache_transport_trial', job['env']['PUBLICATION_REQUIRE_VERIFIED'])
        names = [step.get('name') for step in job['steps']]
        for name in ('Verify live admission and exact distribution roots',
                     'Reserve exact official cache recovery identity',
                     'Verify pinned upstream handoff against actual appliance exposure',
                     'Record freshly verified cache destination'):
            self.assertIn(name, names)
        self.assertLess(names.index('Inspect current public cache before closure materialization'),
                        names.index('Restore authenticated qualified Nix closures without builders'))
        source = (ROOT/'modules/ci/authority/_source/publish.sh').read_text()
        self.assertIn('${PUBLICATION_REQUIRE_VERIFIED:-false} == true', source)
        self.assertIn('cache_readback+=(--require-verified)', source)
        self.assertIn('MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED PUBLICATION_CURL_WORKER_SOURCE', source)

    def test_profile_counts_reconcile(self):
        self.route(1)
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'MAESTRO_CI_DIAGNOSTICS': 'true', 'RUNNER_TEMP': temp}):
            diagnostics.COUNTERS.clear(); diagnostics.PROFILES.clear()
            diagnostic_requests.ROWS.clear(); diagnostic_requests.INSPECTIONS.clear()
            diagnostic_requests.OVERFLOW = False
            with diagnostic_requests.inspection(), transport.Reader(8) as read:
                self.assertEqual(read(url(1))[0], 200)
                self.assertEqual(read(url(1))[0], 200)
            value = {'measurements': dict(diagnostics.COUNTERS), 'profiles': dict(diagnostics.PROFILES),
                     'requests': diagnostic_requests.snapshot()}
            diagnostic_requests.validate(value)
            profile = value['profiles']['transport']['public-http']
            self.assertEqual(profile['calls'], 2)
            self.assertEqual(profile['subprocessLaunches'], 1)
            self.assertEqual(profile['requestStarts'], 2)
            self.assertEqual(profile['successfulConnections'], 1)
            self.assertEqual(profile['measuredReads'], 2)
            self.assertIsNone(profile['httpAttempts'])
            self.assertIsNone(profile['wireBytes'])


if __name__ == '__main__':
    unittest.main()
