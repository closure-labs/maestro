#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enrich the runtime SBOM using exact derivations, never guessed versions."""
import hashlib
import json
from pathlib import Path
import shlex
import re
import subprocess
import sys
from urllib.parse import quote


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def properties(component):
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def attributes(derivation):
    env = derivation.get("env", {})
    return {**env, **json.loads(env.get("__json", "{}"))}


def patches(derivation):
    value = attributes(derivation).get("patches", [])
    return shlex.split(value) if isinstance(value, str) else value


def realize_patch_inputs(derivations):
    # Substituting a runtime closure does not fetch its build-time patches.
    # Resolve only missing patch outputs, never entire package build inputs.
    missing = {str(p) for drv in derivations.values() for p in patches(drv) if not Path(p).is_file()}
    if not missing:
        return
    inputs = sorted({p for drv in derivations.values() for p in drv.get("inputDrvs", {})})
    producers = {}
    for start in range(0, len(inputs), 64):
        records = json.loads(subprocess.check_output(["nix", "derivation", "show", *inputs[start:start + 64]]))
        for path, record in records.items():
            for output, info in record["outputs"].items():
                if info.get("path") in missing:
                    producers[info["path"]] = path + "^" + output
    if missing - producers.keys():
        raise ValueError("missing immutable patch producer metadata")
    subprocess.run(["nix", "build", "--no-link", *sorted(set(producers.values()))], check=True)


def enrich(system, supply, context, derivations):
    if system.get("bomFormat") != "CycloneDX" or not system.get("components"):
        raise ValueError("system inventory is empty or invalid")
    if supply.get("bomFormat") != "CycloneDX" or not supply.get("components"):
        raise ValueError("XO inventory is empty or invalid")
    npm = [c for c in supply["components"] if c.get("purl", "").startswith("pkg:npm/")]
    if not npm or any(not c.get("version") for c in npm):
        raise ValueError("XO supply inventory has no versioned installed npm packages")
    for component in system["components"]:
        props = properties(component)
        drv = props.get("nix:drv_path")
        if not drv or drv not in derivations:
            raise ValueError(f"missing derivation metadata: {component.get('bom-ref')}")
        attrs = attributes(derivations[drv])
        name, version = attrs.get("pname"), attrs.get("version")
        if not (name and version):
            # Legacy derivations expose the formal name instead of pname/version.
            # Parse that immutable derivation attribute, not an output suffix.
            match = re.match(r"^(.+?)-([0-9].*)$", str(attrs.get("name", "")))
            if match:
                name, version = match.groups()
        if name == "nodejs-slim":
            name = "nodejs"
        if name and version:
            component["name"], component["version"] = str(name), str(version)
            component["purl"] = "pkg:nix/" + quote(str(name), safe="") + "@" + quote(str(version), safe="")
            component["type"] = "library"
            # Old inferred CPEs may describe another product/version. Let Grype
            # derive candidates from the authoritative package identity.
            component.pop("cpe", None)
        elif component.get("version"):
            # sbomnix may know the identity of legacy derivations without pname.
            if not component.get("purl"):
                raise ValueError("versioned component lacks a package URL")
        else:
            component["type"] = "file"
            component.pop("cpe", None)
        patch_records = [{"path": str(p), "sha256": hashlib.sha256(Path(p).read_bytes()).hexdigest()} for p in patches(derivations[drv])]
        component.setdefault("properties", []).extend([
            {"name": "maestro:derivation", "value": drv},
            {"name": "maestro:source", "value": json.dumps(attrs.get("src"), sort_keys=True)},
            {"name": "maestro:patches", "value": json.dumps(patch_records, sort_keys=True)},
            {"name": "maestro:derivationDigest", "value": digest(derivations[drv])},
        ])
    refs = {c["bom-ref"] for c in system["components"]}
    for component in supply["components"]:
        if not component.get("purl") or (component.get("type") == "library" and not component.get("version") and not component["purl"].startswith("pkg:github/")):
            raise ValueError("unscannable XO library component")
        if component["bom-ref"] in refs:
            raise ValueError("colliding supply component identity")
        system["components"].append(component)
        refs.add(component["bom-ref"])
    system.setdefault("dependencies", []).extend(supply.get("dependencies", []))
    root = system.get("metadata", {}).get("component", {}).get("bom-ref")
    xo_root = supply.get("metadata", {}).get("component", {}).get("bom-ref")
    for dep in system["dependencies"]:
        if dep["ref"] == root:
            dep["dependsOn"] = sorted(set(dep.get("dependsOn", [])) | {xo_root})
        if dep["ref"] not in refs and dep["ref"] != root:
            raise ValueError("dependency references an unknown component")
        if not set(dep.get("dependsOn", [])) <= refs:
            raise ValueError("dependency edge references an unknown component")
    if not root or not xo_root:
        raise ValueError("missing inventory root identity")
    system.setdefault("properties", []).extend([
        {"name": "maestro:inventoryVersion", "value": "2"},
        {"name": "maestro:runtimeContext", "value": json.dumps(context, sort_keys=True)},
        {"name": "maestro:runtimeContextDigest", "value": digest(context)},
        {"name": "maestro:installedNpmCount", "value": str(len(npm))},
    ])
    return system


def main():
    system_path, supply_path, context_path = map(Path, sys.argv[1:])
    system = json.loads(system_path.read_text())
    drvs = sorted({properties(c)["nix:drv_path"] for c in system["components"]})
    derivations = {}
    for start in range(0, len(drvs), 64):
        derivations.update(json.loads(subprocess.check_output(["nix", "derivation", "show", *drvs[start:start + 64]])))
    realize_patch_inputs(derivations)
    result = enrich(system, json.loads(supply_path.read_text()), json.loads(context_path.read_text()), derivations)
    system_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
