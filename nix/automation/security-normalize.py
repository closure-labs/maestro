#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep separate security decisions for distinct immutable component instances."""
import hashlib
import json
from pathlib import Path
import sys


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalize(report, sbom, scanner_version):
    props = {p["name"]: p["value"] for p in sbom.get("properties", [])}
    if props.get("maestro:inventoryVersion") != "2":
        raise ValueError("security inventory is incomplete or predates inventory v2")
    context = props.get("maestro:runtimeContextDigest", "")
    if len(context) != 64 or digest(json.loads(props["maestro:runtimeContext"])) != context:
        raise ValueError("invalid runtime context binding")
    components = {c["bom-ref"]: c for c in sbom["components"]}
    if len(components) != len(sbom["components"]):
        raise ValueError("duplicate inventory identity")
    findings = {}
    for match in report["matches"]:
        artifact, vulnerability = match["artifact"], match["vulnerability"]
        component = components.get(artifact["id"])
        if component is None:
            candidates = [c for c in components.values() if c.get("purl") == artifact.get("purl") and c.get("name") == artifact["name"] and c.get("version") == artifact["version"]]
            if len(candidates) != 1:
                raise ValueError("scanner match has ambiguous or absent immutable component identity")
            component = candidates[0]
        component_props = {p["name"]: p["value"] for p in component.get("properties", [])}
        binding = {
            "component_ref": component["bom-ref"], "purl": component["purl"],
            "output_path": component_props.get("nix:storePath", component_props.get("nix:output_path")),
            "derivation": component_props.get("maestro:derivation"),
            "derivation_digest": component_props.get("maestro:derivationDigest"),
            "source": component_props.get("maestro:source"),
            "patches": component_props.get("maestro:patches"),
            "hashes": component.get("hashes", []), "runtime_context": context,
            "manifest_path": component_props.get("xo-nixpkg:manifestPath"),
            "scanner": scanner_version, "normalizer": "3",
            "namespace": vulnerability["namespace"],
            "advisory_digest": digest(vulnerability),
            "match_digest": digest(match["matchDetails"]),
            "match_types": sorted({d["type"] for d in match["matchDetails"]}),
        }
        severity = vulnerability["severity"].lower()
        if severity not in {"critical", "high", "medium", "low", "negligible", "unknown"}:
            raise ValueError("unsupported scanner severity")
        finding = {"advisory": vulnerability["id"], "component": artifact["name"],
                   "version": artifact["version"], "severity": severity, "scanner": "grype",
                   "identity": digest(binding), "binding": binding,
                   "evidence": {"parents": sorted(d["ref"] for d in sbom.get("dependencies", []) if component["bom-ref"] in d.get("dependsOn", [])),
                                "urls": vulnerability.get("urls", [])}}
        findings[(finding["advisory"], finding["identity"], severity)] = finding
    return [findings[k] for k in sorted(findings)]


if __name__ == "__main__":
    report, inventory, version, output = map(Path, sys.argv[1:])
    findings = normalize(json.loads(report.read_text()), json.loads(inventory.read_text()), json.loads(version.read_text()))
    output.write_text(json.dumps(findings, sort_keys=True, indent=2) + "\n")
