#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact closure transport integrity without touching a real Nix store."""
from copy import deepcopy
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

spec = importlib.util.spec_from_file_location('distribution_cache', Path(__file__).parents[4] / 'modules/ci/authority/_source/distribution-cache.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)
ROOT = '/nix/store/' + 'a' * 32 + '-runtime'
NAR = 'sha256-' + 'A' * 43 + '='
roots = [{'storePath': ROOT, 'narHash': NAR}]
CHILD = '/nix/store/' + 'b' * 32 + '-dependency'
CHILD_NAR = 'sha256-' + base64.b64encode(bytes([1]) * 32).decode()


def reject(call):
    try:
        call()
    except (ValueError, OSError, tarfile.TarError):
        return
    raise AssertionError('unsafe cache transport accepted')


class Nix:
    def __init__(self):
        self.calls = []
        self.nar_hash = NAR

    def __call__(self, args):
        self.calls.append(args)
        if args[:3] == ['nix', 'path-info', '--json']:
            return json.dumps({ROOT: {'narHash': self.nar_hash}}).encode()
        if args[:3] == ['nix', 'store', 'verify']:
            assert '--recursive' in args and '--no-trust' in args
            return b''
        assert args[:2] == ['nix', 'copy']
        if args[2] == '--to':
            assert parse_qs(urlparse(args[3]).query) == {'compression': ['zstd'], 'compression-level': ['3']}
            output = Path(urlparse(args[3]).path)
            output.mkdir()
            (output / 'nix-cache-info').write_text('StoreDir: /nix/store\n')
            (output / 'nar').mkdir()
            (output / 'nar' / 'fixture.nar.xz').write_bytes(b'compressed immutable NAR bytes')
            (output / ('a' * 32 + '.narinfo')).write_text('StorePath: ' + ROOT + '\n')
        else:
            assert args[2] == '--from' and args[4] == '--no-check-sigs'
            restored = Path(urlparse(args[3]).path)
            assert (restored / 'nar' / 'fixture.nar.xz').read_bytes() == b'compressed immutable NAR bytes'
        return b''


class ClosureNix(Nix):
    def __init__(self):
        super().__init__()
        self.retained = {ROOT: {'narHash': NAR}, CHILD: {'narHash': CHILD_NAR}}
        self.local = deepcopy(self.retained)
        self.metadata_timeouts = []

    def __call__(self, args, timeout=1800):
        if args[:3] == ['nix', 'path-info', '--json'] and '--recursive' in args:
            self.metadata_timeouts.append(timeout)
            self.calls.append(args)
            return json.dumps(self.retained if '--store' in args else self.local).encode()
        return super().__call__(args)


with tempfile.TemporaryDirectory() as temporary:
    base = Path(temporary)
    nix = Nix()
    with patch.object(cache, 'command', side_effect=nix), patch.object(cache, 'PART_BYTES', 4096):
        first, second = base / 'first', base / 'second'
        manifest = cache.export(first, roots)
        again = cache.export(second, roots)
        assert manifest == again and len(manifest['parts']) > 1
        cache.restore(first, manifest, roots)
        assert any(args[:3] == ['nix', 'copy', '--from'] for args in nix.calls)
        before = len(nix.calls)
        bad = deepcopy(manifest)
        bad['archiveSha256'] = 'f' * 64
        reject(lambda: cache.restore(first, bad, roots))
        assert len(nix.calls) == before
        extra = first / 'distribution-cache.tar.part-999'
        extra.write_bytes(b'extra')
        reject(lambda: cache.restore(first, manifest, roots))
        extra.unlink()
        part = first / sorted(manifest['parts'])[0]
        original = part.read_bytes()
        part.write_bytes(b'x' + original[1:])
        reject(lambda: cache.restore(first, manifest, roots))
        part.write_bytes(original)
        extra.symlink_to(part)
        bad = deepcopy(manifest)
        bad['parts'][extra.name] = {'sha256': cache.digest(part), 'size': part.stat().st_size}
        reject(lambda: cache.restore(first, bad, roots))
        extra.unlink()
        nix.nar_hash = 'sha256-' + 'B' * 43 + '='
        reject(lambda: cache.restore(first, manifest, roots))
        reject(lambda: cache.export(first, roots))

    # Repair upload identities come from the authenticated retained cache, and
    # only become usable after the imported closure's actual bytes are checked.
    metadata = base / 'repair-closure.json'
    nix = ClosureNix()
    with patch.object(cache, 'command', side_effect=nix):
        cache.restore(first, manifest, roots, closure_metadata=metadata)
    assert json.loads(metadata.read_text()) == nix.retained
    assert nix.metadata_timeouts == [30, 30]
    assert [args[:3] for args in nix.calls] == [
        ['nix', 'path-info', '--json'], ['nix', 'copy', '--from'],
        ['nix', 'path-info', '--json'], ['nix', 'store', 'verify'],
        ['nix', 'path-info', '--json']]
    assert '--store' in nix.calls[0] and '--recursive' in nix.calls[0]
    assert '--store' not in nix.calls[-1] and '--recursive' in nix.calls[-1]
    metadata.unlink()
    nix = ClosureNix()
    # Identical store path/root hashes cannot hide different child NAR bytes.
    nix.local[CHILD]['narHash'] = 'sha256-' + 'C' * 43 + '='
    with patch.object(cache, 'command', side_effect=nix):
        reject(lambda: cache.restore(first, manifest, roots, closure_metadata=metadata))
    assert not metadata.exists()
    assert any(args[:3] == ['nix', 'store', 'verify'] for args in nix.calls)
    nix = ClosureNix()
    nix.retained[ROOT]['narHash'] = 'sha256-' + 'C' * 43 + '='
    with patch.object(cache, 'command', side_effect=nix):
        reject(lambda: cache.restore(first, manifest, roots, closure_metadata=metadata))
    assert not metadata.exists()
    assert not any(args[:3] == ['nix', 'copy', '--from'] for args in nix.calls)

    # The publication wrapper must authenticate/materialize the retained packet
    # even when every approved root already exists in the local runner store.
    environment = {
        'MAESTRO_DECISION_CORE': str(Path(cache.__file__).parent / 'decisions'),
        'MAESTRO_DISTRIBUTION_CACHE_SOURCE': str(Path(cache.__file__)),
        'MAESTRO_SYSTEM_ROOT': str(base), 'DECISION_SCANS': str(base / 'scans.json'),
        'DECISION_PRODUCT': str(base / 'product.json'),
        'DECISION_EVIDENCE_DIRECTORY': str(first),
        'DISTRIBUTION_CLOSURE_METADATA': str(metadata)}
    with patch.dict(os.environ, environment, clear=True):
        spec = importlib.util.spec_from_file_location('repair_restore',
                                                     Path(cache.__file__).with_name('distribution-restore.py'))
        restore = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(restore)
        events = []
        transfer = SimpleNamespace(verify_roots=Mock(),
                                   restore=Mock(side_effect=lambda *args, **kwargs: events.append('restore')))
        fake_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        with patch.object(restore.common, 'config', return_value={}), \
                patch.object(restore.common, 'gate', side_effect=lambda *args: events.append('gate')), \
                patch.object(restore.common, 'load_json', side_effect=[{'transport': manifest}, {'products': {'maestro': roots[0]}}]), \
                patch.object(restore.Path, 'exists', return_value=True), \
                patch.object(restore.packet_materialization, 'materialize', side_effect=lambda *args: events.append('materialize')) as materialize, \
                patch.object(restore.importlib.util, 'spec_from_file_location', return_value=fake_spec), \
                patch.object(restore.importlib.util, 'module_from_spec', return_value=transfer):
            restore.main()
        assert events == ['gate', 'materialize', 'restore']
        materialize.assert_called_once_with(first)
        transfer.verify_roots.assert_not_called()
        transfer.restore.assert_called_once_with(first, manifest, roots, closure_metadata=str(metadata))

    # Every malicious archive fails before nix copy can import anything.
    def malicious(member_name, member_type=tarfile.REGTYPE, duplicate=False):
        directory = base / ('hostile-' + hashlib.sha256((member_name + member_type.decode() + str(duplicate)).encode()).hexdigest()[:12])
        directory.mkdir()
        archive = directory / 'distribution-cache.tar.part-000'
        with tarfile.open(archive, 'w') as output:
            info = tarfile.TarInfo('nix-cache-info')
            info.size = 1
            output.addfile(info, io.BytesIO(b'x'))
            info = tarfile.TarInfo(member_name)
            info.type = member_type
            if member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = '/nix/store/escape'
            output.addfile(info)
            if duplicate:
                output.addfile(info)
        manifest = {'schema': 1, 'parts': {archive.name: {'sha256': cache.digest(archive), 'size': archive.stat().st_size}},
                    'archiveSha256': cache.digest(archive), 'archiveSize': archive.stat().st_size}
        with patch.object(cache, 'command', side_effect=AssertionError('unsafe archive reached Nix')):
            reject(lambda: cache.restore(directory, manifest, roots))
    malicious('../escape')
    malicious('/absolute')
    malicious('nar/link', tarfile.SYMTYPE)
    malicious('nar/hardlink', tarfile.LNKTYPE)
    malicious('nar/device', tarfile.CHRTYPE)
    malicious('nar/duplicate', duplicate=True)
print('Distribution closure transport, deterministic chunks, hostile archives and exact NAR fixtures passed.')
