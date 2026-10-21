#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Download data from a completed protected producer without executing its tree."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import zipfile
import sys
sys.path.insert(0, os.environ.get('MAESTRO_DECISION_CORE', str(Path(__file__).with_name('decisions'))))
import operations
import common

REPOSITORY = "closure-labs/maestro"
WORKFLOWS = {".github/workflows/ci.yml": "maestro-security-report",
             ".github/workflows/security.yml": "maestro-weekly-security-report",
             ".github/workflows/release.yml": "maestro-release-product",
             ".github/workflows/release-continuation.yml": "maestro-release-product"}


def api(endpoint):
    return json.loads(operations.run(["gh", "api", "--method", "GET", f"repos/{REPOSITORY}/{endpoint}"],
                                             text=True, capture_output=True, check=True, timeout=30).stdout)


def trusted(run):
    return (run.get("repository", {}).get("full_name") == REPOSITORY
            and run.get("head_branch") == "main" and run.get("event") in ("push", "schedule", "workflow_dispatch", "workflow_run")
            and run.get("status") == "completed" and run.get("conclusion") == "success"
            and run.get("path", "").split("@")[0] in WORKFLOWS
            and re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", "")))


def extract(archive, output):
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if not entries or len(entries) > 1024 or sum(e.file_size for e in entries) > 32 * 1024**3:
            raise ValueError("Artifact exceeds bounded inventory")
        names = set()
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if (entry.filename in names or path.is_absolute() or "\\" in entry.filename
                    or any(part in ("", ".", "..") for part in entry.filename.rstrip("/").split("/"))
                    or ((entry.external_attr >> 16) & 0o170000) not in (0, 0o100000, 0o040000)):
                raise ValueError("Artifact has unsafe or duplicate members")
            names.add(entry.filename)
        source.extractall(output)


def main():
    proposal_hash = os.environ.get('CANDIDATE_PROPOSAL_HASH', '')
    identity = os.environ.get('CANDIDATE_RUN', '')
    workflow_filter = os.environ.get('CANDIDATE_WORKFLOW', '')
    admitted = None
    if proposal_hash:
        if (not re.fullmatch(r'[0-9a-f]{64}', proposal_hash)
                or (identity and not re.fullmatch(r'[1-9][0-9]{0,19}', identity))
                or os.environ.get('PUBLICATION_METADATA_ONLY') != 'true'
                or os.environ.get('CANDIDATE_RELEASE_ONLY') != 'true'):
            raise ValueError('Exact official cache recovery requires one canonical proposal and metadata-only release selection')
        if not identity:
            # No Actions discovery for an exact retained proposal. Its reader
            # checks current admission before materializing retained metadata.
            raise SystemExit(3)
        if workflow_filter not in ('', '.github/workflows/security.yml'):
            raise ValueError('Fresh official cache recovery requires security maintenance')
        workflow_filter = '.github/workflows/security.yml'
        cfg = common.config(Path(os.environ.get('MAESTRO_SYSTEM_ROOT', '.')) / 'nix/automation/decision-policy.json', live=True)
        _, records = common.ledger(cfg)
        admitted = common.admitted_release(cfg, records, proposal_hash)
    if os.environ.get('PUBLICATION_METADATA_ONLY') == 'true' and not os.environ.get('CANDIDATE_RUN'):
        raise SystemExit(3)
    if identity:
        if not re.fullmatch(r"[1-9][0-9]{0,19}", identity):
            raise ValueError("Invalid candidate run ID")
        candidates = [api(f"actions/runs/{identity}")]
    else:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        event = json.loads(Path(event_path).read_text()) if event_path else {}
        triggering = event.get("workflow_run", {})
        if triggering.get("path", "").split("@")[0] in WORKFLOWS:
            candidates = [api(f"actions/runs/{int(triggering['id'])}")]
        else:
            # Bounded discovery is an optimization. No matching evidence fails
            # closed; historical records are never treated as current authority.
            candidates = api("actions/runs?branch=main&status=success&per_page=100")["workflow_runs"]
    selected = None
    release_only = os.environ.get("CANDIDATE_RELEASE_ONLY") == "true"
    for run in candidates:
        path = run.get("path", "").split("@")[0]
        if admitted is not None and (type(run.get('id')) is not int or run['id'] != int(identity)
                or type(run.get('run_attempt')) is not int or run['run_attempt'] <= 0):
            raise ValueError('Fresh official cache recovery producer differs from requested run')
        if not trusted(run) or (workflow_filter and path != workflow_filter):
            continue
        if release_only and path == ".github/workflows/ci.yml":
            continue
        inventory = api(f"actions/runs/{run['id']}/artifacts?per_page=100")
        if inventory["total_count"] > 100:
            raise ValueError("Producer artifact inventory exceeds bound")
        artifact_name = "maestro-release-product" if release_only else WORKFLOWS[path]
        artifacts = [a for a in inventory["artifacts"] if a["name"] == artifact_name and not a["expired"]]
        if len(artifacts) == 1:
            selected = run, artifacts[0]
            break
    if selected is None:
        if admitted is not None:
            raise ValueError('Exact fresh official recovery needs one trusted release artifact')
        # A distinct discovery result permits only the immutable OCI fallback;
        # API, archive and integrity failures never reach that fallback.
        raise SystemExit(3)
    run, artifact = selected
    digest = artifact.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Artifact has no immutable archive digest")
    output = Path(os.environ.get("DECISION_DIRECTORY", "candidate-evidence"))
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryFile() as archive:
        operations.run(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip"],
                       stdout=archive, check=True, timeout=900)
        archive.seek(0)
        if hashlib.file_digest(archive, "sha256").hexdigest() != digest.removeprefix("sha256:"):
            raise ValueError("Downloaded artifact archive differs from authenticated metadata")
        archive.seek(0)
        extract(archive, output)
    # Upload-artifact preserves the common directory prefix only for multiple
    # source directories. Resolve the two explicitly supported layouts.
    evidence = output if (output / "scans.json").is_file() else output / "security-report"
    scans = json.loads((evidence / "scans.json").read_text())
    product = json.loads((evidence / "product.json").read_text())
    producer = scans["producer"]
    if admitted is not None and any(type(producer.get(key)) is not int for key in ('runId', 'runAttempt')):
        raise ValueError('Fresh recovery requires typed native producer identity')
    if (scans["revision"] != product["revision"] or producer.get("revision", scans["revision"]) != run["head_sha"]
            or scans["repository"] != REPOSITORY or product["repository"] != REPOSITORY
            or producer["workflow"] != run["path"].split("@")[0] or producer["runId"] != run["id"]
            or producer["runAttempt"] != run["run_attempt"]):
        raise ValueError("Candidate documents differ from authoritative producer")
    if admitted is not None and common.canonical_hash(product) != common.canonical_hash(admitted['payload']['product']):
        raise ValueError('Fresh recovery changed the exact admitted product')
    tags = {match[1] for name in product["assets"] if (match := re.fullmatch(r"maestro-(v[0-9]+\.[0-9]+\.[0-9]+)\.iso\.sha256", name))}
    if product["assets"] and len(tags) != 1:
        raise ValueError("Official product lacks one immutable release tag")
    values = {"available": "true", "candidate_run": str(run["id"]), "source_sha": product["revision"],
              "evidence_directory": str(evidence), "product": str(evidence / "product.json"),
              "scans": str(evidence / "scans.json"), "release": "true" if product["assets"] else "false",
              "release_tag": next(iter(tags), ""), "release_version": next(iter(tags), "").removeprefix("v")}
    for destination in (os.environ.get("GITHUB_OUTPUT"), os.environ.get("GITHUB_ENV")):
        if destination:
            with Path(destination).open("a") as target:
                for key, value in values.items():
                    name = {"product": "DECISION_PRODUCT", "scans": "DECISION_SCANS",
                            "evidence_directory": "DECISION_EVIDENCE_DIRECTORY", "candidate_run": "DECISION_CANDIDATE_RUN",
                            "source_sha": "DECISION_SOURCE_SHA", "release": "DECISION_IS_RELEASE",
                            "release_tag": "RELEASE_TAG", "release_version": "RELEASE_VERSION"}.get(key, key) if destination == os.environ.get("GITHUB_ENV") else key
                    target.write(f"{name}={value}\n")
    print(json.dumps(values, sort_keys=True))


if __name__ == "__main__":
    main()
