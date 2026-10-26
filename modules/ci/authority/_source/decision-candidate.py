#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind completed native observations to the exact qualified distribution roots."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def command(*args):
    return subprocess.check_output(args, text=True, timeout=180).strip()


def producer_identity():
    """The caller owns the run; a reusable workflow owns its signature."""
    run_id = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    run = json.loads(command("gh", "api", f"repos/closure-labs/maestro/actions/runs/{run_id}/attempts/{attempt}"))
    workflow = run.get("path", "").split("@")[0]
    signer = os.environ.get("DECISION_PRODUCER_WORKFLOW", ".github/workflows/ci.yml")
    if (workflow not in (".github/workflows/ci.yml", ".github/workflows/release.yml", ".github/workflows/release-continuation.yml")
            or run.get("head_branch") != "main" or run.get("head_sha") != os.environ["GITHUB_SHA"]
            or run.get("repository", {}).get("full_name") != "closure-labs/maestro"
            or run.get("id") != run_id or run.get("run_attempt") != attempt):
        raise ValueError("Candidate builder differs from authoritative protected caller")
    return {"workflow": workflow, "signerWorkflow": signer, "revision": run["head_sha"],
            "runId": run_id, "runAttempt": attempt}


def prepare(native, root, revision, run, attempt, workflow, now=None):
    if native.get("status") != "complete" or native.get("scannerHealth") != "healthy":
        raise ValueError("Complete healthy native evidence is required")
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or run < 1 or attempt < 1:
        raise ValueError("An immutable producer identity is required")
    now = now or dt.datetime.now(dt.timezone.utc)
    # The native scan timestamp is authoritative. Transporting an old scan
    # must never turn it into a fresh observation.
    scanned = dt.datetime.fromisoformat(native["scannedAt"].replace("Z", "+00:00"))
    if scanned.tzinfo is None or not dt.timedelta() <= now - scanned < dt.timedelta(hours=24):
        raise ValueError("Native observation timestamp is stale or in the future")
    scans = {
        "schema": 1, "repository": "closure-labs/maestro", "revision": revision,
        "producer": {"workflow": workflow, "runId": run, "runAttempt": attempt},
        "scannedAt": scanned.isoformat(), "expiresAt": (scanned + dt.timedelta(hours=24)).isoformat(),
        "profiles": {"maestro": native},
    }
    primary = command("nix", "eval", "--accept-flake-config", "--raw",
                      f"path:{root}#nixosConfigurations.maestro.config.system.build.toplevel.outPath")
    identities = {subject["storePath"]: subject for subject in native["subjects"]}
    if primary not in identities:
        raise ValueError("The appliance root is absent from scanned subjects")
    roots = {}
    targets = json.loads((root / "modules/ci/graph/_lib/plans.json").read_text())["publish"]["targets"]
    for target in targets:
        path = command("nix", "eval", "--accept-flake-config", "--raw",
                       f"path:{root}#{target['attribute']}.outPath")
        if path not in identities:
            raise ValueError("A distribution root is absent from the native inventory")
        roots[target["name"]] = {**identities[path], "profile": "maestro"}
    qualification = json.loads(command("nix", "eval", "--accept-flake-config", "--json",
                                      f"path:{root}#lib.ciInstallerQualification.x86_64-linux"))
    coverage = native.get("coverage", {})
    if coverage.get("contract") != "maestro-distribution-v2" or coverage.get("manifest") != qualification:
        raise ValueError("Native installer coverage differs from evaluated qualification manifest")
    for name, path in qualification["roots"].items():
        if path not in identities or name in roots:
            raise ValueError("Installer qualification root is missing or collides with publication roots")
        roots[name] = {**identities[path], "profile": "maestro"}
    if set(identities) != {primary, *(value["storePath"] for value in roots.values())}:
        raise ValueError("Native subjects differ from exact complete distribution")
    product = {"schema": 1, "repository": "closure-labs/maestro", "revision": revision,
               "products": {"maestro": identities[primary]}, "roots": roots, "assets": {}}
    return scans, product


def main():
    root = Path(os.environ.get("MAESTRO_SYSTEM_ROOT", ".")).resolve()
    output = Path(os.environ.get("SECURITY_OUTPUT", "security-report"))
    native = json.loads((output / "security-result.json").read_text())
    revision = os.environ.get("SOURCE_SHA") or os.environ["GITHUB_SHA"]
    if command("git", "-C", str(root), "rev-parse", "HEAD") != revision:
        raise ValueError("Producer checkout differs from immutable revision")
    scans, product = prepare(native, root, revision, int(os.environ["GITHUB_RUN_ID"]),
                             int(os.environ["GITHUB_RUN_ATTEMPT"]),
                             os.environ.get("DECISION_PRODUCER_WORKFLOW", ".github/workflows/ci.yml"))
    scans["producer"] = producer_identity()
    scans["productProducer"] = dict(scans["producer"])
    # Retain exact inventories and lockfile as data for future native rescans.
    inventory = Path(os.environ.get("SECURITY_INVENTORY", "candidate"))
    retained = output / "inventory"
    retained.mkdir(exist_ok=True)
    for name in ("maestro-system.cdx.json", "xen-orchestra-supply.cdx.json"):
        shutil.copyfile(inventory / name, retained / name)
    shutil.copyfile(root / "modules/features/operator/menu/_source/frontend/Cargo.lock", retained / "Cargo.lock")
    release_dir = os.environ.get("DECISION_RELEASE_DIRECTORY")
    if release_dir:
        directory = Path(release_dir)
        for path in sorted(directory.iterdir()):
            if path.is_symlink() or not path.is_file() or not re.fullmatch(r"[A-Za-z0-9_.+-]+", path.name):
                raise ValueError("Release assets must be bounded regular named files")
            with path.open("rb") as source:
                product["assets"][path.name] = hashlib.file_digest(source, "sha256").hexdigest()
        if not product["assets"]:
            raise ValueError("An official release cannot have an empty asset inventory")
    transfer = Path(os.environ["MAESTRO_DISTRIBUTION_CACHE_SOURCE"])
    spec = importlib.util.spec_from_file_location("distribution_cache", transfer)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    roots = {v["storePath"]: {"storePath": v["storePath"], "narHash": v["narHash"]}
             for v in [*product["products"].values(), *product["roots"].values()]}
    scans["transport"] = module.export(output, list(roots.values()))
    for name, value in (("scans.json", scans), ("product.json", product)):
        (output / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
