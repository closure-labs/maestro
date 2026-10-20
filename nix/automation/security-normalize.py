#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep separate security decisions for distinct immutable component instances."""
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sys
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
import ipaddress


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


def component_locations(component):
    """Enumerate actual shipped files; never substitute a guessed install path."""
    props = {p["name"]: p["value"] for p in component.get("properties", [])}
    manifest = props.get("xo-nixpkg:manifestPath")
    root = str(PurePosixPath(manifest).parent) if manifest else props.get("nix:storePath", props.get("nix:output_path"))
    if not isinstance(root, str) or not re.fullmatch(r"/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[^/]+(?:/[^/]+)*", root):
        raise ValueError("missing immutable shipped component location")
    if str(PurePosixPath(root)) != root or any(p in {".", ".."} for p in root.split("/")):
        raise ValueError("ambiguous shipped component location")
    path = Path(root)
    if not path.exists():
        raise ValueError("shipped component location is unavailable")
    if manifest and not Path(manifest).is_file():
        raise ValueError("installed npm manifest is unavailable")
    locations = []
    if path.is_file():
        locations.append(root)
    else:
        def failed(error):
            raise error
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
            # A symlink is itself shipped evidence. Do not walk into another
            # package's output or a nested npm dependency with another identity.
            for name in list(dirs):
                entry = Path(directory, name)
                if entry.is_symlink():
                    locations.append(str(entry))
                if manifest and name == "node_modules":
                    dirs.remove(name)
            locations.extend(str(Path(directory, name)) for name in files)
    if not locations:
        raise ValueError("component has no shipped file exposure")
    if any("\\" in path or "\x00" in path or str(PurePosixPath(path)) != path for path in locations):
        raise ValueError("ambiguous shipped file exposure")
    return sorted(set(locations))


def exposure_bindings(component, locations, sbom):
    props = {p["name"]: p["value"] for p in component.get("properties", [])}
    root = props.get("nix:storePath", props.get("nix:output_path"))
    # npm manifests are nested in an XO derivation output. Resolve that root
    # using its independently enriched component metadata, not its store name.
    if props.get("xo-nixpkg:manifestPath"):
        root = "/".join(props["xo-nixpkg:manifestPath"].split("/")[:4])
        producers = []
        for candidate in sbom["components"]:
            candidate_props = {p["name"]: p["value"] for p in candidate.get("properties", [])}
            if candidate_props.get("nix:output_path", candidate_props.get("nix:storePath")) == root and candidate_props.get("maestro:outputName", candidate_props.get("xo-nixpkg:outputName")):
                candidate_props["maestro:outputName"] = candidate_props.get("maestro:outputName", candidate_props.get("xo-nixpkg:outputName"))
                producers.append(candidate_props)
        if not producers or len({p["maestro:outputName"] for p in producers}) != 1:
            raise ValueError("npm exposure lacks exact output producer metadata")
        props = producers[0]
    output_name = props.get("maestro:outputName", props.get("xo-nixpkg:outputName"))
    if not isinstance(output_name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", output_name):
        raise ValueError("missing native output name for stable exposure")
    if not isinstance(root, str) or any(not p.startswith(root + "/") for p in locations):
        raise ValueError("shipped file escapes its exact derivation output")
    return [{"location": path, "outputName": output_name, "relativePath": path[len(root) + 1:]} for path in locations]


def observations(report, sbom):
    # Validate the complete inventory and existing immutable match bindings first.
    legacy = normalize(report, sbom, {})
    components = {c["bom-ref"]: c for c in sbom["components"]}
    bindings = {(f["advisory"], f["binding"]["component_ref"]): f["binding"] for f in legacy}
    exposures = {}
    result = []
    severities = ["Negligible", "Low", "Medium", "High", "Critical"]
    for match in report["matches"]:
        artifact, vulnerability = match["artifact"], match["vulnerability"]
        component = components.get(artifact["id"])
        if component is None:
            candidates = [c for c in components.values() if c.get("purl") == artifact.get("purl") and c.get("name") == artifact["name"] and c.get("version") == artifact["version"]]
            if len(candidates) != 1:
                raise ValueError("ambiguous scanner component")
            component = candidates[0]
        purl = component.get("purl", "")
        if not re.fullmatch(r"pkg:[a-z][a-z0-9.+-]*/[^\s]+@[^\s@?#]+(?:[?#][^\s]+)?", purl) or not component.get("version"):
            raise ValueError("observation requires a versioned package URL")
        if artifact.get("version") != component["version"] or artifact.get("purl") not in (None, purl):
            raise ValueError("scanner component disagrees with immutable inventory")
        related = match.get("relatedVulnerabilities", [])
        if not isinstance(related, list) or any(not isinstance(v, dict) for v in related):
            raise ValueError("malformed related vulnerabilities")
        records = [vulnerability, *related]
        aliases = set()
        scores, exploited, levels = [], False, []
        for record in records:
            identifier = record.get("id")
            if not isinstance(identifier, str) or not identifier:
                raise ValueError("missing advisory identity")
            aliases.add(identifier)
            native_aliases = record.get("aliases", [])
            if not isinstance(native_aliases, list):
                raise ValueError("invalid advisory aliases")
            for alias in native_aliases:
                if not isinstance(alias, str) or not alias:
                    raise ValueError("invalid advisory alias")
                aliases.add(alias)
            level = record.get("severity", "Unknown").title()
            if level not in [*severities, "Unknown"]:
                raise ValueError("unsupported related advisory severity")
            levels.append(level)
            for cvss in record.get("cvss", []):
                score = cvss.get("metrics", {}).get("baseScore")
                if isinstance(score, bool) or not isinstance(score, (float, int)) or not math.isfinite(score) or not 0 <= score <= 10:
                    raise ValueError("invalid CVSS evidence")
                scores.append(score)
            flag = record.get("knownExploited", False)
            if isinstance(flag, list):
                flag = bool(flag)
            if type(flag) is not bool:
                raise ValueError("invalid exploitation evidence")
            exploited |= flag
        severity = max((s for s in levels if s != "Unknown"), key=severities.index, default="Unknown")
        binding = bindings[(vulnerability["id"], component["bom-ref"])]
        if component["bom-ref"] not in exposures:
            locations = component_locations(component)
            exposures[component["bom-ref"]] = (locations, exposure_bindings(component, locations, sbom))
        locations, exposure = exposures[component["bom-ref"]]
        fixes = vulnerability.get("fix", {}).get("versions", [])
        if not isinstance(fixes, list) or any(not isinstance(version, str) for version in fixes):
            raise ValueError("invalid fix versions")
        result.append({"component": purl, "advisory": vulnerability["id"], "aliases": sorted(aliases),
                       "severity": vulnerability["severity"].title(), "admissionSeverity": severity,
                       "knownExploited": exploited, "cvss": max(scores, default=None),
                       "fixVersions": fixes,
                       "locations": locations, "locationCoverage": "complete",
                       "exposureBindings": exposure,
                       "evidence": {"binding": binding, "rawMatchSha256": digest(match)}})
    return result


def rust_observations(audit, sbom):
    entries = audit["vulnerabilities"]["list"]
    if not isinstance(entries, list):
        raise ValueError("missing RustSec observations")
    if not entries:
        return []
    menus = [c for c in sbom["components"] if c.get("name") == "maestro-menu"]
    if len(menus) != 1:
        raise ValueError("RustSec requires the exact shipped maestro-menu component")
    locations = component_locations(menus[0])
    bindings = exposure_bindings(menus[0], locations, sbom)
    from cvss import CVSS3, CVSS4
    result = []
    for entry in entries:
        advisory, package = entry["advisory"], entry["package"]
        vector = advisory.get("cvss")
        severity, score = "Unknown", None
        if vector:
            calculator = CVSS4(vector) if vector.startswith("CVSS:4.") else CVSS3(vector)
            score = float(calculator.scores()[0])
            severity = calculator.severities()[0].title()
            if severity == "None":
                severity = "Negligible"
        result.append({"component": "pkg:cargo/" + quote(package["name"], safe="") + "@" + quote(package["version"], safe=""),
                       "advisory": advisory["id"], "aliases": advisory.get("aliases", []),
                       "severity": severity, "admissionSeverity": severity, "cvss": score,
                       "knownExploited": False, "fixVersions": entry.get("versions", {}).get("patched", []),
                       "locations": locations, "locationCoverage": "complete",
                       "exposureBindings": bindings,
                       "evidence": {"source": "Cargo.lock dependency audit; shipped executable exposure is conservative",
                                    "rawRustSecSha256": digest(entry), "package": package}})
    return result


def security_context(sbom):
    props = {p["name"]: p["value"] for p in sbom["properties"]}
    runtime = json.loads(props["maestro:runtimeContext"]).get("runtime")
    if runtime is None:
        return None
    required = {"allowedTCPPorts", "allowedUDPPorts", "managementCIDRs", "ssh", "xoUser", "User", "Group",
                "CapabilityBoundingSet", "AmbientCapabilities", "storage", "fileRestore", "sudo"}
    if not isinstance(runtime, dict) or not required <= runtime.keys():
        raise ValueError("incomplete native security runtime policy")

    def privilege(value):
        if isinstance(value, list):
            return [privilege(item) for item in value]
        if isinstance(value, dict):
            return {key: privilege(item) for key, item in value.items()}
        if not isinstance(value, str) or not value.startswith("/nix/store/"):
            return value
        match = re.fullmatch(r"(/nix/store/[a-z0-9]{32}-[^/\s]+)(/[^\s]*)?(.*)", value)
        if not match:
            return value  # Ambiguous policies remain exact, never silently equivalent.
        candidates = []
        for component in sbom["components"]:
            cp = {p["name"]: p["value"] for p in component.get("properties", [])}
            if cp.get("nix:output_path", cp.get("nix:storePath")) == match[1] and cp.get("maestro:outputName"):
                purl = component.get("purl", "")
                if "@" in purl:
                    identity = re.sub(r"@[^?#]+(?=[?#]|$)", "", purl)
                else:
                    identity = "inventory:" + component["name"]
                candidates.append(identity + "#" + cp["maestro:outputName"] + (match[2] or "") + match[3])
        return "nix-privilege:" + candidates[0] if candidates and len(set(candidates)) == 1 else value

    def ports(key):
        values = runtime[key]
        if not isinstance(values, list) or any(type(value) is not int or not 1 <= value <= 65535 for value in values):
            raise ValueError("invalid native firewall policy")
        return sorted(set(values))

    def caps(key):
        values = runtime[key]
        if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values):
            raise ValueError("invalid native capability policy")
        return sorted(set(values))

    storage = runtime["storage"]
    flags = {key: storage[key] for key in ("enableNFS", "enableCIFS", "enableVHD")}
    flags["fileRestore"] = runtime["fileRestore"]["enable"]
    if any(type(value) is not bool for value in flags.values()):
        raise ValueError("invalid native helper policy")
    cidrs = runtime["managementCIDRs"]
    if not isinstance(cidrs, list) or not cidrs:
        raise ValueError("missing native management ranges")
    return {"schema": 1, "tcpPorts": ports("allowedTCPPorts"), "udpPorts": ports("allowedUDPPorts"),
            "managementCIDRs": sorted({str(ipaddress.ip_network(value, strict=False)) for value in cidrs}),
            "ssh": privilege(runtime["ssh"]), "execution": {key: runtime[key] for key in ("xoUser", "User", "Group")},
            "capabilities": caps("CapabilityBoundingSet"), "ambientCapabilities": caps("AmbientCapabilities"),
            "helpers": flags, "sudo": privilege(runtime["sudo"]), "mountsDir": storage["mountsDir"]}


def security_result(report, sbom, audit, database, started, evidence):
    now = datetime.now(timezone.utc)
    built = datetime.fromisoformat(database["built"].replace("Z", "+00:00"))
    if database.get("valid") is not True or built.tzinfo is None or built > now + timedelta(minutes=5) or now - built > timedelta(hours=48):
        raise ValueError("invalid or stale Grype database")
    props = {p["name"]: p["value"] for p in sbom["properties"]}
    subjects = json.loads(props.get("maestro:inventoryRoots", "null"))
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("inventory lacks bound publication closure subjects")
    expected_path = os.environ.get("DECISION_ROOTS_JSON")
    if expected_path and sorted(json.loads(Path(expected_path).read_text()), key=lambda s: s["storePath"]) != sorted(subjects, key=lambda s: s["storePath"]):
        raise ValueError("scan roots differ from bound inventory roots")
    # A zero-match scan still needs complete installed identities. Validate
    # coverage before finding selection, so absent packages cannot look clean.
    npm_count = 0
    for component in sbom["components"]:
        if component.get("type") == "file":
            continue
        purl = component.get("purl", "")
        if not component.get("version") or not re.fullmatch(r"pkg:[a-z][a-z0-9.+-]*/[^\s]+@[^\s@?#]+(?:[?#][^\s]+)?", purl):
            raise ValueError("incomplete installed package identity")
        component_props = {p["name"]: p["value"] for p in component.get("properties", [])}
        if purl.startswith("pkg:npm/"):
            npm_count += 1
            manifest = component_props.get("xo-nixpkg:manifestPath")
            if not isinstance(manifest, str) or not manifest.startswith("/nix/store/") or str(PurePosixPath(manifest)) != manifest or ".." in manifest.split("/"):
                raise ValueError("installed npm component lacks immutable manifest")
            native = json.loads(Path(manifest).read_text())
            if native.get("name") != component["name"] or native.get("version") != component["version"]:
                raise ValueError("installed npm identity differs from shipped manifest")
        else:
            root = component_props.get("nix:storePath", component_props.get("nix:output_path"))
            output_name = component_props.get("maestro:outputName", component_props.get("xo-nixpkg:outputName"))
            if not isinstance(root, str) or not Path(root).exists() or not output_name:
                raise ValueError("installed native component lacks exact output coverage")
    expected_npm = props.get("maestro:installedNpmCount")
    if expected_npm is not None and (not expected_npm.isdigit() or int(expected_npm) != npm_count or npm_count == 0):
        raise ValueError("installed npm inventory coverage changed")
    result = {"schema": 1, "status": "complete", "scannerHealth": "healthy",
            "startedAt": started, "scannedAt": now.isoformat().replace("+00:00", "Z"),
            "subjects": subjects, "database": database, "observations": observations(report, sbom) + rust_observations(audit, sbom),
            "evidence": evidence, "runtimeContextDigest": props["maestro:runtimeContextDigest"]}
    context = security_context(sbom)
    if context is None:
        raise ValueError("Maestro native evidence requires actual runtime security policy")
    result["securityContext"] = context
    return result


if __name__ == "__main__" and sys.argv[1:2] == ["--result"]:
    output_dir, inventory, started = sys.argv[2:]
    output = Path(output_dir)
    paths = {"grype": output / "maestro-system.grype.json", "inventory": Path(inventory),
             "rustsec": output / "cargo-audit.json", "grypeDatabase": output / "grype-database.json",
             "grypeVersion": output / "grype-version.json", "cargoAuditVersion": output / "cargo-audit-version.txt",
             "rustsecDatabase": output / "rustsec-database.json",
             "inputHashes": output / "inputs.sha256"}
    evidence = {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size} for name, path in paths.items()}
    document = security_result(*(json.loads(paths[k].read_text()) for k in ["grype", "inventory", "rustsec", "grypeDatabase"]), started, evidence)
    # Create only a fresh completed result; a failed attempt leaves no stale pass.
    with (output / "security-result.json").open("x") as handle:
        handle.write(json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n")
elif __name__ == "__main__":
    report, inventory, version, output = map(Path, sys.argv[1:])
    findings = normalize(json.loads(report.read_text()), json.loads(inventory.read_text()), json.loads(version.read_text()))
    output.write_text(json.dumps(findings, sort_keys=True, indent=2) + "\n")
