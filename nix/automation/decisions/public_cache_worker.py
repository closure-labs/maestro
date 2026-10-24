# SPDX-License-Identifier: Apache-2.0
"""Private, process-isolated libcurl worker. Never reads authority or writes destinations."""
import base64
import ctypes as c
import json
import os
import sys
import time
from urllib.parse import urlparse

LIBRARY = '@LIBCURL@'  # Replaced with the pinned store path by the native package.
BODY_LIMIT = 2 * 1024 * 1024
ORIGINS = {'https://maestro.cachix.org', 'https://cache.nixos.org', 'https://xen-orchestra-ce.cachix.org'}
TRANSIENT_HTTP = {408, 429, 500, 502, 503, 504, 522, 524}
TRANSIENT_ERRORS = {7, 18, 28, 52, 55, 56}


class Option(c.Structure):
    _fields_ = [('name', c.c_char_p), ('id', c.c_int), ('type', c.c_int), ('flags', c.c_uint)]


Write = c.CFUNCTYPE(c.c_size_t, c.c_void_p, c.c_size_t, c.c_size_t, c.c_void_p)
Prerequisite = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_char_p, c.c_char_p, c.c_int, c.c_int)


class Engine:
    def __init__(self):
        self.lib = lib = c.CDLL(LIBRARY)
        lib.curl_global_init.argtypes = [c.c_long]
        if lib.curl_global_init(3):
            raise ValueError('Public transport initialization failed')
        lib.curl_easy_init.restype = c.c_void_p
        lib.curl_easy_cleanup.argtypes = [c.c_void_p]
        lib.curl_easy_perform.argtypes = [c.c_void_p]
        lib.curl_easy_setopt.argtypes = [c.c_void_p, c.c_int]
        lib.curl_easy_getinfo.argtypes = [c.c_void_p, c.c_int]
        lib.curl_easy_option_by_name.argtypes = [c.c_char_p]
        lib.curl_easy_option_by_name.restype = c.POINTER(Option)
        self.handle = lib.curl_easy_init()
        if not self.handle:
            raise ValueError('Public transport allocation failed')
        self.body = bytearray()
        self.write_callback = Write(self.write)
        self.prerequisite_callback = Prerequisite(self.before_request)
        self.starts = self.denied = 0
        self.deadline = self.retry_deadline = 0
        # Match the pinned curl CLI's native options, including its TLS floor.
        for name, value in (
                ('PROTOCOLS_STR', 'https'), ('USERAGENT', 'Nix/2.34'), ('CONNECTTIMEOUT_MS', 5000),
                ('BUFFERSIZE', 102400), ('NOPROGRESS', 1), ('MAXREDIRS', 50), ('CERTINFO', 1),
                ('SSLVERSION', 6), ('SSL_VERIFYPEER', 1), ('SSL_VERIFYHOST', 2),
                ('FOLLOWLOCATION', 0), ('TCP_KEEPALIVE', 1), ('WRITEFUNCTION', self.write_callback),
                ('PREREQFUNCTION', self.prerequisite_callback)):
            self.set(name, value)
        self.set('MAXFILESIZE_LARGE', c.c_longlong(BODY_LIMIT))
        # curl-tool certificate environment conventions are not libcurl options.
        bundle = os.environ.get('CURL_CA_BUNDLE') or os.environ.get('SSL_CERT_FILE')
        if bundle:
            self.set('CAINFO', bundle)
        if os.environ.get('SSL_CERT_DIR'):
            self.set('CAPATH', os.environ['SSL_CERT_DIR'])

    def set(self, name, value):
        option = self.lib.curl_easy_option_by_name(name.encode())
        if not option:
            raise ValueError('Pinned public transport option unavailable')
        if isinstance(value, str):
            value = c.c_char_p(value.encode())
        elif type(value) is int:
            value = c.c_long(value)
        if self.lib.curl_easy_setopt(self.handle, option.contents.id, value):
            raise ValueError('Public transport option failed')

    def info(self, key, wide=False):
        value = c.c_longlong() if wide else c.c_long()
        if self.lib.curl_easy_getinfo(self.handle, key, c.byref(value)):
            raise ValueError('Public transport measurement failed')
        return value.value

    def write(self, pointer, size, count, ignored):
        length = size * count
        if len(self.body) + length > BODY_LIMIT:
            return 0
        self.body.extend(c.string_at(pointer, length))
        return length

    def before_request(self, *ignored):
        now = time.monotonic()
        if self.starts >= 2 or now >= self.deadline or (self.starts and now >= self.retry_deadline):
            self.denied += 1
            return 1
        self.starts += 1
        return 0

    def read(self, url, deadline):
        parsed = urlparse(url)
        if (parsed.scheme != 'https' or parsed.username or parsed.password or parsed.fragment or parsed.query
                or f'{parsed.scheme}://{parsed.netloc}' not in ORIGINS):
            raise ValueError('Invalid public metadata origin')
        started = time.monotonic()
        if type(deadline) not in (int, float) or not started < deadline <= started + 31:
            raise ValueError('Invalid public metadata deadline')
        self.deadline, self.retry_deadline = deadline, min(deadline, started + 25)
        self.starts = self.denied = 0
        connections = retries = 0
        status = None
        data = b''
        self.set('URL', url)
        for attempt in range(2):
            if time.monotonic() >= self.deadline:
                break
            self.body.clear()
            self.set('TIMEOUT_MS', max(1, int((self.deadline - time.monotonic()) * 1000)))
            error = self.lib.curl_easy_perform(self.handle)
            code = self.info(0x200002)  # CURLINFO_RESPONSE_CODE
            connections += self.info(0x20001a)  # CURLINFO_NUM_CONNECTS: successful connects only
            retry_after = self.info(0x600039, wide=True)  # CURLINFO_RETRY_AFTER
            status, data = (None, b'') if error else (code, bytes(self.body))
            transient = error in TRANSIENT_ERRORS or (not error and code in TRANSIENT_HTTP)
            if not transient or attempt or self.starts >= 2:
                break
            delay = max(1, retry_after)
            if time.monotonic() + delay >= self.retry_deadline:
                break
            time.sleep(delay)
            retries += 1
        return {'schema': 1, 'status': status, 'body': base64.b64encode(data).decode('ascii'),
                'successfulConnections': connections, 'requestStarts': self.starts,
                'deniedRequestStarts': self.denied, 'explicitRetries': retries,
                'metadataBytes': len(data)}

    def close(self):
        if self.handle:
            self.lib.curl_easy_cleanup(self.handle)
            self.handle = None
            self.lib.curl_global_cleanup()


def main():
    engine = Engine()
    try:
        while True:
            line = sys.stdin.buffer.readline(2049)
            if not line:
                return
            if len(line) > 2048 or not line.endswith(b'\n'):
                raise ValueError('Invalid public metadata request')
            value = json.loads(line)
            if not isinstance(value, dict) or set(value) != {'url', 'deadline'} or not isinstance(value['url'], str):
                raise ValueError('Invalid public metadata request')
            result = engine.read(value['url'], value['deadline'])
            sys.stdout.write(json.dumps(result, separators=(',', ':'), allow_nan=False) + '\n')
            sys.stdout.flush()
    finally:
        engine.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError):
        # Do not expose URLs, certificate paths, proxy settings or library errors.
        sys.exit(1)
