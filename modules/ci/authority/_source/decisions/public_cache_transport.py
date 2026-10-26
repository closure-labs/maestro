# SPDX-License-Identifier: Apache-2.0
"""Inspection-scoped public metadata workers with bounded process-family cleanup."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse
import diagnostics
import operations

FLAG = 'MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED'
BODY_LIMIT = 2 * 1024 * 1024
REPLY_LIMIT = 4 * ((BODY_LIMIT + 2) // 3) + 2048
ORIGINS = {'https://maestro.cachix.org', 'https://cache.nixos.org', 'https://xen-orchestra-ce.cachix.org'}
METRICS = ('successfulConnections', 'requestStarts', 'deniedRequestStarts', 'explicitRetries', 'metadataBytes')
PUBLIC_ENV = ('PATH', 'LANG', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE', 'NIX_SSL_CERT_FILE',
              'http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
              'no_proxy', 'NO_PROXY')


def enabled():
    value = os.environ.get(FLAG, 'false')
    if value not in ('true', 'false'):
        raise ValueError('Invalid public cache transport flag')
    return value == 'true'


class Reader:
    def __init__(self, workers):
        if workers != 8:
            raise ValueError('Invalid public metadata concurrency')
        self.workers = workers
        self.children = {}
        self.lock = threading.Lock()
        self.failed = threading.Event()

    def __enter__(self):
        return self

    def __exit__(self, *ignored):
        self.failed.set()
        # All process families get the same concurrent cleanup bound, including
        # idle workers. No reader/connection survives an inspection boundary.
        with ThreadPoolExecutor(max_workers=self.workers) as cleanup:
            list(cleanup.map(self.close, list(self.children.values())))

    @staticmethod
    def close(child):
        if getattr(child, '_public_closed', False):
            return
        try:
            if child.poll() is None:
                operations.terminate(child)
            else:
                child.communicate()
        finally:
            child._public_closed = True
            for stream in (child.stdin, child.stdout):
                if stream:
                    stream.close()

    def child(self):
        identity = threading.get_ident()
        with self.lock:
            if identity not in self.children:
                if len(self.children) >= self.workers or self.failed.is_set():
                    raise ValueError('Public metadata worker unavailable')
                source = os.environ.get('PUBLICATION_CURL_WORKER_SOURCE')
                if not source or not Path(source).is_file():
                    raise ValueError('Pinned public metadata worker unavailable')
                environment = {key: os.environ[key] for key in PUBLIC_ENV if key in os.environ}
                environment['PYTHONDONTWRITEBYTECODE'] = '1'
                child = subprocess.Popen([sys.executable, source], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True, env=environment)
                os.set_blocking(child.stdout.fileno(), False)
                self.children[identity] = child
                diagnostics.profile('transport', 'public-http', launches=1)
            return self.children[identity]

    @staticmethod
    def reply(child, deadline):
        data = bytearray()
        cancelled = operations.CANCELLATION.get()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or (cancelled is not None and cancelled.is_set()):
                raise subprocess.TimeoutExpired(['public-metadata-worker'], 30)
            ready, _, _ = select.select([child.stdout], [], [], min(remaining, 0.1))
            if not ready:
                continue
            chunk = os.read(child.stdout.fileno(), min(65536, REPLY_LIMIT + 1 - len(data)))
            if not chunk:
                raise ValueError('Public metadata worker closed')
            data.extend(chunk)
            if len(data) > REPLY_LIMIT:
                raise ValueError('Public metadata reply exceeds bound')
            if b'\n' in data:
                if not data.endswith(b'\n') or data.count(b'\n') != 1:
                    raise ValueError('Invalid public metadata reply framing')
                return bytes(data)

    def __call__(self, url, head=False):
        parsed = urlparse(url)
        if (head or parsed.username or parsed.password or parsed.fragment or parsed.query
                or f'{parsed.scheme}://{parsed.netloc}' not in ORIGINS
                or not re.fullmatch(r'/[0123456789abcdfghijklmnpqrsvwxyz]{32}\.narinfo', parsed.path)):
            raise ValueError('Invalid public cache metadata read')
        diagnostics.count('publicTransportInvocations')
        diagnostics.profile('transport', 'public-http', wrappers=1)
        child = None
        measured = False
        with diagnostics.measuring('transport', 'public-http'):
            try:
                if self.failed.is_set():
                    return None, b''
                deadline = time.monotonic() + operations.remaining(30)
                cancelled = operations.CANCELLATION.get()
                if cancelled is not None and cancelled.is_set():
                    raise subprocess.TimeoutExpired(['public-metadata-worker'], 30)
                child = self.child()
                request = (json.dumps({'url': url, 'deadline': deadline}, allow_nan=False) + '\n').encode()
                if len(request) > 2048:
                    raise ValueError('Public metadata request exceeds bound')
                child.stdin.write(request)
                raw = self.reply(child, deadline)
                diagnostics.profile('transport', 'public-http', captured=len(raw))
                value = json.loads(raw)
                if (not isinstance(value, dict) or set(value) != {'schema', 'status', 'body', *METRICS}
                        or type(value['schema']) is not int or value['schema'] != 1
                        or any(type(value[key]) is not int or value[key] < 0 for key in METRICS)
                        or value['requestStarts'] > 2 or value['explicitRetries'] > 1
                        or value['deniedRequestStarts'] > 2 or value['successfulConnections'] > 16
                        or value['metadataBytes'] > BODY_LIMIT
                        or (value['status'] is not None and (type(value['status']) is not int or not 100 <= value['status'] <= 599))
                        or not isinstance(value['body'], str)):
                    raise ValueError('Invalid public metadata worker result')
                body = base64.b64decode(value['body'], validate=True)
                if len(body) != value['metadataBytes'] or (value['status'] is None and body):
                    raise ValueError('Invalid public metadata worker bytes')
                diagnostics.profile('transport', 'public-http', retries=value['explicitRetries'],
                                    connections=value['successfulConnections'], starts=value['requestStarts'],
                                    denied=value['deniedRequestStarts'], metadata=value['metadataBytes'], measured=1)
                measured = True
                if value['status'] is None:
                    self.failed.set()
                return value['status'], body
            except subprocess.TimeoutExpired:
                self.failed.set()
                if child:
                    self.close(child)
                raise
            except (OSError, ValueError, TypeError):
                self.failed.set()
                if child:
                    self.close(child)
                return None, b''
            finally:
                if not measured:
                    diagnostics.profile('transport', 'public-http', unmeasured=1)
