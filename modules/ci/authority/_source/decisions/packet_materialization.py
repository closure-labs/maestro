# SPDX-License-Identifier: Apache-2.0
"""Required payload materialization after metadata-only destination inspection."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import decision_packets as packets
import operations


def materialize(directory):
    directory=Path(directory)
    source_path=directory.with_suffix('.source.json')
    if not source_path.exists():return
    source=json.loads(source_path.read_text())
    with tempfile.TemporaryDirectory(prefix='publication-materialize-') as temporary, operations.budget(900):
        temporary=Path(temporary); previous=os.environ.get('DOCKER_CONFIG')
        try:
            registry=temporary/'registry';registry.mkdir();os.environ['DOCKER_CONFIG']=str(registry)
            operations.run(['oras','login','ghcr.io','--username',os.environ['GITHUB_ACTOR'],'--password-stdin'],
                           input=os.environ['REGISTRY_TOKEN'],text=True,capture_output=True,check=True,timeout=30)
            descriptor=packets.metadata(source['reference'],source['sha256'],'decision-packet.json',producer=source['producer'])
            scans=json.loads((directory/'scans.json').read_bytes());product=json.loads((directory/'product.json').read_bytes())
            producer=dict(scans['producer'],repository=product['repository'],
                          revision=scans['producer'].get('revision',product['revision']),sourceRevision=product['revision'])
            if producer!=descriptor['producer']:raise ValueError('Materialization producer differs from gated metadata')
            for name in ('product.json','scans.json'):
                path=directory/name; record=descriptor['files'].get(name,{})
                if path.is_symlink() or not path.is_file() or path.stat().st_size!=record.get('size') or packets.file_hash(path)!=record.get('sha256'):
                    raise ValueError('Materialization packet differs from gated metadata bytes')
            target=temporary/'payload'
            packets.fetch(source['reference'],target,source['sha256'])
            (target/'decision-packet.json').unlink()
            for path in target.rglob('*'):
                operations.remaining(900)
                if path.is_file():
                    output=directory/path.relative_to(target)
                    packets.install_member(path,output,directory)
            source_path.unlink()
        finally:
            if previous is None:os.environ.pop('DOCKER_CONFIG',None)
            else:os.environ['DOCKER_CONFIG']=previous
