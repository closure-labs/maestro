# SPDX-License-Identifier: Apache-2.0
"""Decision-only scheduling and fresh read-only verification of retained evidence."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

import common
import decision_authority as authority
import decision_packets as packets
import operations
import scheduling
from security_decisions import normalize_findings

GENERATORS = ('modules/ci/inventory/_source/security-inventory.py', 'modules/ci/inventory/_source/security-inventory.sh',
              'modules/ci/security/_source/security-normalize.py', 'modules/ci/security/_source/security-scan.sh',
              'modules/ci/inventory/_source/security-applicability.sh', 'modules/ci/inventory/_source/security-applicability.json',
              'modules/ci/authority/_source/decisions/fingerprints.py',
              'modules/features/installer/_source/qualification-assets.sh', 'modules/features/installer/_source/boot-media.sh')
GENERATOR_PACKAGES = ('maestro-ci-security-inventory', 'maestro-ci-security-scan',
                      'maestro-ci-qualification-assets', 'maestro-ci-boot-media', 'maestro-ci-decision-candidate')


class UnavailableEvidence(ValueError):
    """Fresh full validation remains necessary; no retained result is authorized."""


def publication_intent(cfg, records):
    """Normalize a same-run scheduling hint against current native selectors."""
    if (os.environ.get('MAESTRO_DECISION_ONLY_REUSE_ENABLED', 'false') != 'true'
            or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_run'
            or os.environ.get('CANDIDATE_RUN') or os.environ.get('CANDIDATE_PROPOSAL_HASH')
            or os.environ.get('CANDIDATE_RELEASE_ONLY') == 'true' or os.environ.get('DECISION_RELEASE_ONLY') == 'true'):
        return None
    event = common.load_json(Path(os.environ['GITHUB_EVENT_PATH']))
    trigger = event.get('workflow_run', {})
    if type(trigger.get('id')) is not int or trigger['id'] <= 0:
        return None
    run = authority.github_api(f'repos/{cfg["repository"]}/actions/runs/{trigger["id"]}')
    producer = {'workflow': '.github/workflows/ci.yml', 'runId': run.get('id'),
                'runAttempt': run.get('run_attempt'), 'revision': run.get('head_sha')}
    common.verify_producer(cfg, producer, run.get('head_sha'), require_main=True)
    common.require(run.get('head_sha') == trigger.get('head_sha') and run.get('path') == '.github/workflows/ci.yml',
                   'Publication intent trigger differs from protected CI producer')
    inventory = authority.github_api(f'repos/{cfg["repository"]}/actions/runs/{run["id"]}/artifacts?per_page=100')
    common.require(type(inventory.get('total_count')) is int and inventory['total_count'] <= 100,
                   'Publication intent artifact inventory exceeds bound')
    name = f'maestro-retained-publication-intent-{run["id"]}-{run["run_attempt"]}'
    artifacts = [item for item in inventory['artifacts'] if item.get('name') == name and not item.get('expired')]
    if not artifacts:
        return None
    common.require(len(artifacts) == 1, 'Ambiguous retained publication intent')
    artifact = artifacts[0]
    common.require(type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= 128 * 1024
                   and isinstance(artifact.get('digest'), str) and re.fullmatch(r'sha256:[a-f0-9]{64}', artifact['digest']),
                   'Publication intent lacks bounded immutable archive identity')
    with tempfile.TemporaryFile() as archive:
        operations.run(['gh', 'api', f'repos/{cfg["repository"]}/actions/artifacts/{artifact["id"]}/zip'],
                       stdout=archive, check=True, timeout=90)
        archive.seek(0)
        common.require(hashlib.file_digest(archive, 'sha256').hexdigest() == artifact['digest'][7:],
                       'Publication intent archive digest differs')
        archive.seek(0)
        with zipfile.ZipFile(archive) as source:
            files = source.infolist()
            common.require(len(files) == 1 and files[0].filename == 'retained-publication-intent.json'
                           and files[0].file_size <= 64 * 1024, 'Publication intent has unexpected archive members')
            hint = json.loads(source.read(files[0]))
    if hint.get('reused') is not True:
        return None
    common.require(hint.get('schema') == 1 and hint.get('status') == 'verified' and hint.get('eligible') is True
                   and hint.get('source') == run['head_sha'] and hint.get('runId') == run['id']
                   and hint.get('runAttempt') == run['run_attempt']
                   and type(hint.get('runId')) is int and type(hint.get('runAttempt')) is int,
                   'Publication hint differs from successful retained verification')
    common.require(not os.environ.get('CANDIDATE_WORKFLOW')
                   or hint.get('producer', {}).get('workflow') == os.environ['CANDIDATE_WORKFLOW'],
                   'Publication hint differs from explicit producer workflow selector')
    product_decision = records.get(hint.get('productDecisionHash'))
    common.require(product_decision is not None and product_decision['kind'] == 'release-product'
                   and product_decision['payload']['disposition'] == 'accepted', 'Hint lacks a current native product decision')
    product = product_decision['payload']['product']
    active_hash, active = common.active_release(cfg, records, product, authenticate=False)
    security_hash, security = common.active_security(cfg, records, authenticate=False)
    common.require(active_hash == hint['productDecisionHash'] and active == product_decision
                   and common.canonical_hash(product) == hint.get('productHash')
                   and security_hash == hint.get('securityDecisionHash') and security is not None
                   and security['payload']['disposition'] == 'accepted', 'Publication hint conflicts with current protected selection')
    original = dict(hint['producer'], repository=cfg['repository'],
                    revision=hint['producer'].get('revision', product['revision']), sourceRevision=product['revision'])
    candidates = {common.canonical_hash(value['payload']['packet']): (digest, value)
                  for digest, value in ((active_hash, active), (security_hash, security))
                  if value['payload'].get('packet', {}).get('producer') == original}
    common.require(len(candidates) == 1, 'Publication hint has no unambiguous retained producer binding')
    digest, selected = next(iter(candidates.values()))
    return {'decisionHash': digest, 'proposal': selected, 'productHash': hint['productHash'],
            'productDecisionHash': active_hash, 'securityDecisionHash': security_hash}


def git(root, *args):
    return operations.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(root), *args],
                          capture_output=True, check=True, timeout=30).stdout


def inspect(root, base, source):
    if not all(isinstance(value, str) and authority.SHA.fullmatch(value) for value in (base, source)):
        return None
    if git(root, 'rev-parse', 'HEAD').decode().strip() != source:
        raise ValueError('Decision-only checkout differs from immutable source')
    raw = git(root, 'diff', '--no-renames', '--raw', '--no-abbrev', '-z', base, source).split(b'\0')
    if len(raw) != 3 or raw[-1] != b'':
        return None
    header, name, _ = raw
    if not re.fullmatch(rb':000000 100644 0{40} [a-f0-9]{40} A', header):
        return None
    path = name.decode('utf-8')
    if not re.fullmatch(r'automation/decisions/(security|releases)/[a-f0-9]{64}\.json', path):
        return None
    contents = git(root, 'show', source + ':' + path)
    if len(contents) > authority.MAX_PROPOSAL_BYTES:
        raise ValueError('Decision-only record exceeds native bound')
    with tempfile.TemporaryDirectory() as directory:
        file = Path(directory) / 'proposal.json'
        file.write_bytes(contents)
        proposal = common.load_json(file)
    if authority.proposal_path(proposal) != path or contents != (json.dumps(proposal, sort_keys=True, indent=2) + '\n').encode():
        raise ValueError('Decision-only proposal is not canonical native content')
    if proposal['kind'] not in ('security-findings', 'release-product'):
        return None
    packet = proposal['payload'].get('packet')
    if (not isinstance(packet, dict) or set(packet) != {'reference', 'sha256', 'producer'}
            or not packets.REFERENCE.fullmatch(packet.get('reference', ''))
            or not common.HASH.fullmatch(packet.get('sha256', '')) or not isinstance(packet['producer'], dict)):
        raise ValueError('Decision-only proposal lacks one immutable retained packet binding')
    return {'schema': 1, 'base': base, 'source': source, 'decisionPath': path,
            'decisionHash': common.canonical_hash(proposal), 'packet': packet,
            'productHash': common.canonical_hash(proposal['payload']['product']) if proposal['kind'] == 'release-product' else None}


def evaluation(reference, *arguments):
    # Candidate evaluation receives public transport settings only. It cannot
    # inherit the read-only authority token, registry credentials or Nix config.
    with tempfile.TemporaryDirectory(prefix='retained-evaluation-') as directory:
        nix_config = Path(directory) / 'nix'
        nix_config.mkdir()
        (nix_config / 'nix.conf').write_text('')
        environment = {key: os.environ[key] for key in ('PATH', 'SSL_CERT_FILE', 'NIX_SSL_CERT_FILE') if key in os.environ}
        environment.update(HOME=directory, XDG_CONFIG_HOME=directory, NIX_USER_CONF_FILES='/dev/null',
                           NIX_CONF_DIR=str(nix_config), NIX_CONFIG='experimental-features = nix-command flakes\n',
                           GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
        result = operations.run(['nix', 'eval', '--json', '--no-write-lock-file', '--no-accept-flake-config',
                                 '--option', 'pure-eval', 'true', '--option', 'allow-import-from-derivation', 'false',
                                 '--option', 'allow-unsafe-native-code-during-evaluation', 'false',
                                 reference, *arguments],
                                env=environment, capture_output=True, check=True, timeout=180)
    return json.loads(result.stdout)


def evaluated_inputs(root):
    graph = evaluation('path:' + str(root) + '#lib.ciQualificationInputs.x86_64-linux')
    return {name + '_input': hashlib.sha256((json.dumps(graph[name], sort_keys=True, separators=(',', ':'),
                                                        ensure_ascii=False) + '\n').encode()).hexdigest()
            for name in ('media', 'evidence')}


def evaluated_generators(reference):
    expression = 'p: { ' + ' '.join(f'"{name}" = p."{name}".outPath;' for name in GENERATOR_PACKAGES) + ' }'
    try:
        values = evaluation(reference + '#packages.x86_64-linux', '--apply', expression)
    except (OSError, subprocess.SubprocessError) as error:
        raise UnavailableEvidence('Evaluated retained generator packages unavailable') from error
    common.require(isinstance(values, dict) and set(values) == set(GENERATOR_PACKAGES)
                   and all(isinstance(value, str) and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\s]+', value)
                           for value in values.values()), 'Invalid actual generator package identities')
    return values


def qualification_state(cfg, producer, directory):
    if producer['workflow'] != '.github/workflows/ci.yml':
        raise UnavailableEvidence('Original producer has no supported CI qualification pointer')
    result = operations.run(['gh', 'run', 'download', str(producer['runId']), '--repo', cfg['repository'],
                             '--name', 'maestro-qualification-state', '--dir', str(directory)],
                            capture_output=True, check=False, timeout=90)
    if result.returncode:
        raise UnavailableEvidence('Original qualification pointer unavailable')
    path = directory / 'maestro-qualification-state.json'
    common.command(['maestro-ci-verify-state', str(path), str(producer['runId'])])
    value = common.load_json(path)
    common.require(value['source_commit'] == producer['revision'], 'Qualification pointer differs from original producer')
    return value


def clean_inputs(root):
    common.require(not git(root, 'status', '--porcelain', '--untracked-files=all').strip()
                   and not git(root, 'ls-files', '--others').strip(),
                   'Candidate inputs are locally modified or contain untracked files')


def source_proposal(root, descriptor):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'proposal.json'
        path.write_bytes(git(root, 'show', descriptor['source'] + ':' + descriptor['decisionPath']))
        return common.load_json(path)


def validate_proposal(cfg, proposal, descriptor, scans, product, records):
    payload = proposal['payload']
    common.require(payload.get('packet') == descriptor['packet'], 'Proposed retained packet changed')
    candidates = dict(records, **{descriptor['decisionHash']: proposal})
    if proposal['kind'] == 'security-findings':
        expected = {profile: normalize_findings(native, profile) for profile, native in scans['profiles'].items()}
        common.require(set(expected) == set(cfg['profiles']) and payload.get('profiles') == expected,
                       'Proposed decision differs from complete retained native findings')
        if 'securityContexts' in payload:
            common.require(common.accepted_contexts(payload) == common.security_contexts(scans),
                           'Proposed policy differs from retained native context')
        common.active_security(cfg, candidates, authenticate=False)
    elif proposal['kind'] == 'release-product':
        common.require(payload.get('disposition') == 'accepted'
                       and common.canonical_hash(payload.get('product')) == common.canonical_hash(product),
                       'Proposed acceptance differs from retained exact product')
        common.active_release(cfg, candidates, product, authenticate=False)
        if product['assets']:
            packet = descriptor['packet']
            manifest = packets.metadata(packet['reference'], packet['sha256'], 'decision-packet.json', producer=packet['producer'])
            common.require(all(manifest['files'].get(name, {}).get('sha256') == digest for name, digest in product['assets'].items()),
                           'Retained asset inventory differs from native product')
    else:
        raise ValueError('Unsupported retained decision kind')


def verify(cfg, root, descriptor, directory):
    clean_inputs(root)
    common.require(inspect(root, descriptor['base'], descriptor['source']) == descriptor,
                   'Retained route descriptor differs from actual decision-only source')
    packet = descriptor['packet']
    directory.mkdir(parents=True, exist_ok=False)
    for name in ('scans.json', 'product.json', 'inputs.sha256', 'inventory/maestro-system.cdx.json',
                 'inventory/xen-orchestra-supply.cdx.json', 'inventory/Cargo.lock'):
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.write_bytes(packets.metadata_bytes(packet['reference'], packet['sha256'], name, producer=packet['producer']))
        except (OSError, subprocess.SubprocessError) as error:
            raise UnavailableEvidence('Retained evidence transport unavailable') from error
    scans = common.load_json(directory / 'scans.json')
    product = common.load_json(directory / 'product.json')
    product_hash = common.canonical_hash(product)
    common.require(descriptor['productHash'] in (None, product_hash), 'Retained product differs from native proposal')
    common.require(packet['producer'] == dict(scans['producer'], repository=cfg['repository'],
                   revision=scans['producer'].get('revision', scans['revision']), sourceRevision=scans['revision']),
                   'Retained scan producer differs from immutable proposal packet')
    expiry = scheduling.observation_expiry(scans, cfg)
    if dt.datetime.now(dt.timezone.utc) >= expiry:
        raise UnavailableEvidence('Retained observations expired')
    original = dict(scans.get('productProducer', scans['producer']))
    original.setdefault('revision', product['revision'])
    common.verify_producer(cfg, original, product['revision'], require_main=True)
    common.scans(directory / 'scans.json', cfg)
    common.product(directory / 'product.json', cfg, scans)
    spec = importlib.util.spec_from_file_location('retained_native', os.environ['MAESTRO_DECISION_RETAINED_SOURCE'])
    retained = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(retained)
    retained.verify_native_files(directory, scans['profiles']['maestro'])
    # A later CI producer can refresh evidence for an older exact product.
    # Its signed qualification pointer owns the evidence identity; the product
    # keeps its original, independently verified producer. Maintenance scans
    # without a CI pointer still need the original unchanged qualification.
    evidence_producer = dict(scans['producer']) if scans['producer']['workflow'] == '.github/workflows/ci.yml' else original
    evidence_producer.setdefault('revision', scans['revision'])
    common.verify_producer(cfg, evidence_producer, scans['revision'], require_main=True)
    with tempfile.TemporaryDirectory() as state_directory:
        state = qualification_state(cfg, evidence_producer, Path(state_directory))
    inputs = evaluated_inputs(root)
    if any(inputs[key] != state[key] for key in inputs):
        raise UnavailableEvidence('Actual evaluated media or evidence identity changed')
    generator_inputs = evaluated_generators('path:' + str(root))
    generator_sources = sorted({state['source_commit'], scans['producer'].get('revision', scans['revision'])})
    for revision in generator_sources:
        if evaluated_generators('github:' + cfg['repository'] + '/' + revision) != generator_inputs:
            raise UnavailableEvidence('Actual evaluated generator package identity changed')
    generators = {}
    for name in GENERATORS:
        current = (root / name).read_bytes()
        # Bind both inventory qualification and the actual scanner producer.
        # A fresh maintenance scan cannot hide a changed generator recipe.
        for revision in generator_sources:
            try:
                response = authority.github_api(f'repos/{cfg["repository"]}/contents/{name}?ref={revision}')
            except (OSError, subprocess.SubprocessError) as error:
                raise UnavailableEvidence('Retained generator source unavailable') from error
            old = authority.decode_blob(response, response['sha'], response['size'])
            if old != current:
                raise UnavailableEvidence('Actual generator identity changed')
        generators[name] = hashlib.sha256(current).hexdigest()
    _, records = common.ledger(cfg)
    validate_proposal(cfg, source_proposal(root, descriptor), descriptor, scans, product, records)
    product_decision, approved = common.active_release(cfg, records, product)
    if approved is None or approved['payload']['disposition'] != 'accepted':
        raise UnavailableEvidence('Product has no existing merged acceptance')
    admission = common.gate(cfg, directory / 'scans.json', directory / 'product.json')
    common.require(admission['productHash'] == product_hash, 'Retained input identity changed during admission')
    if dt.datetime.now(dt.timezone.utc) >= expiry:
        raise UnavailableEvidence('Retained observations expired during verification')
    clean_inputs(root)
    common.require(inspect(root, descriptor['base'], descriptor['source']) == descriptor,
                   'Candidate source changed during retained verification')
    return {'schema': 1, 'status': 'verified', 'eligible': True, 'productHash': product_hash,
            'descriptorHash': common.canonical_hash(descriptor),
            'productDecisionHash': product_decision, 'securityDecisionHash': admission['decisionHash'],
            'source': descriptor['source'], 'producer': scans['producer'], 'productProducer': original,
            'inputs': inputs, 'generators': generators, 'generatorInputs': generator_inputs,
            'expiresAt': expiry.isoformat(), 'authorityClaim': False}


def main():
    parser = common.parser(__doc__)
    parser.add_argument('operation', choices=('inspect', 'verify'))
    parser.add_argument('--root', type=Path, default=Path(os.environ.get('MAESTRO_SYSTEM_ROOT', '.')))
    parser.add_argument('--base', default=os.environ.get('PR_BASE_SHA') or os.environ.get('MERGE_BASE_SHA') or os.environ.get('PUSH_BASE_SHA', ''))
    parser.add_argument('--source', default=os.environ.get('GITHUB_SHA', ''))
    args = parser.parse_args()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.operation == 'inspect':
        descriptor = inspect(args.root, args.base, args.source)
        common.emit({'schema': 1, 'descriptor': descriptor}, args.output)
        return
    enabled = os.environ.get('MAESTRO_DECISION_ONLY_REUSE_ENABLED', 'false')
    common.require(enabled in ('true', 'false'), 'Invalid decision-only experiment flag')
    descriptor = json.loads(os.environ['CI_PLAN']).get('retained_evidence')
    if descriptor is None:
        result = {'schema': 1, 'status': 'not-eligible', 'eligible': False}
    else:
        try:
            cfg = common.config(args.config, live=True, enabled=True)
            login = operations.run(['oras', 'login', 'ghcr.io', '--username', os.environ['GITHUB_ACTOR'], '--password-stdin'],
                                   input=os.environ.get('REGISTRY_TOKEN', os.environ.get('GH_TOKEN', '')),
                                   capture_output=True, text=True, check=False, timeout=30)
            if login.returncode:
                raise UnavailableEvidence('Retained registry metadata unavailable')
            with tempfile.TemporaryDirectory(prefix='retained-readonly-') as directory:
                result = verify(cfg, args.root, descriptor, Path(directory) / 'evidence')
        except (UnavailableEvidence, packets.RegistryUnavailable) as error:
            result = {'schema': 1, 'status': 'full-validation-required', 'eligible': False, 'reason': str(error)}
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
            needs_fresh_validation = isinstance(error, ValueError) and str(error) in {
                'Current human risk acceptance required', 'New or worsened findings require a human decision',
                'Runtime security policy changes require a human decision', 'Expired or future native health',
                'Native scanner database is stale or newer than its observation'}
            result = {'schema': 1, 'status': 'full-validation-required' if needs_fresh_validation else 'blocked',
                      'eligible': False, 'errorType': type(error).__name__}
            if enabled == 'true' and not needs_fresh_validation:
                common.emit(result, args.output)
                return 2
    result['reused'] = enabled == 'true' and result.get('eligible') is True and result.get('status') == 'verified'
    if result['reused']:
        result['operations'] = {name: 'reused/skipped' for name in ('assembly', 'boot', 'scanning', 'signing')}
        result['runId'] = int(os.environ['GITHUB_RUN_ID'])
        result['runAttempt'] = int(os.environ['GITHUB_RUN_ATTEMPT'])
    common.emit(result, args.output)
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
            stream.write('reused=' + str(result['reused']).lower() + '\n')
            if result['reused']:
                stream.write('descriptor_hash=' + result['descriptorHash'] + '\n')


if __name__ == '__main__':
    sys.exit(common.run(main))
