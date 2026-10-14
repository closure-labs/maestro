#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enrich the runtime SBOM using exact derivations, never guessed versions."""
import hashlib
import json
import os
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


def store_path(value):
    if not isinstance(value, str):
        raise ValueError("invalid derivation store path")
    name = value.removeprefix("/nix/store/")
    if not re.fullmatch(r"[0123456789abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+", name):
        raise ValueError(f"invalid derivation store path: {value!r}")
    return "/nix/store/" + name


def decode_derivations(document):
    if not isinstance(document, dict):
        raise ValueError("derivation JSON must be an object")
    enveloped = "derivations" in document
    if enveloped:
        if type(document.get("version")) is not int or document["version"] != 4:
            raise ValueError("unsupported derivation JSON envelope version")
        document = document["derivations"]
    if not isinstance(document, dict):
        raise ValueError("derivation records must be an object")
    records = {}
    for path, record in document.items():
        path = store_path(path)
        if not path.endswith(".drv") or not isinstance(record, dict):
            raise ValueError("invalid derivation record")
        if enveloped and record.get("version") != 4:
            raise ValueError("version-4 envelope contains an incompatible derivation")
        if "version" in record and (type(record["version"]) is not int or record["version"] not in (1, 2, 3, 4)):
            raise ValueError("unsupported derivation record version")
        if path in records:
            raise ValueError("duplicate derivation store identity")
        if not isinstance(record.get("env"), dict):
            raise ValueError("missing derivation environment")
        attributes(record)
        input_derivations(record)
        if not isinstance(record.get("outputs"), dict) or any(not isinstance(info, dict) for info in record["outputs"].values()):
            raise ValueError("invalid derivation outputs")
        records[path] = record
    return records


def read_derivations(paths):
    records = {}
    for start in range(0, len(paths), 64):
        batch = paths[start:start + 64]
        decoded = decode_derivations(json.loads(subprocess.check_output(["nix", "derivation", "show", *batch])))
        if set(batch) != decoded.keys():
            raise ValueError("derivation response does not match requested store identities")
        records.update(decoded)
    return records


def attributes(derivation):
    env = derivation.get("env", {})
    if not isinstance(env, dict):
        raise ValueError("invalid derivation environment")
    if "structuredAttrs" in derivation:
        structured = derivation["structuredAttrs"]
    else:
        encoded = env.get("__json", "{}")
        if not isinstance(encoded, str):
            raise ValueError("invalid encoded derivation attributes")
        structured = json.loads(encoded)
    if not isinstance(structured, dict):
        raise ValueError("invalid structured derivation attributes")
    return {**env, **structured}


def input_derivations(derivation):
    if derivation.get("version") == 4:
        inputs = derivation.get("inputs")
        if not isinstance(inputs, dict):
            raise ValueError("missing version-4 derivation inputs")
        drvs = inputs.get("drvs")
    else:
        drvs = derivation.get("inputDrvs", {})
    if not isinstance(drvs, dict):
        raise ValueError("invalid derivation inputs")
    return [store_path(path) for path in drvs]


def output_path(derivation, output, info):
    # Version 4 omits the path from fixed-output specifications; the builder's
    # output environment still records the exact immutable store identity.
    path = info.get("path")
    env_path = derivation.get("env", {}).get(output)
    if path is not None:
        path = store_path(path)
    if env_path is not None:
        env_path = store_path(env_path)
    if path and env_path and path != env_path:
        raise ValueError("inconsistent derivation output identity")
    return path or env_path


def patches(derivation):
    value = attributes(derivation).get("patches", [])
    value = shlex.split(value) if isinstance(value, str) else value
    if not isinstance(value, list) or any(not isinstance(path, str) or not path for path in value):
        raise ValueError("invalid derivation patch paths")
    return value


def patch_store_root(path):
    parts = path.split("/")
    if len(parts) < 4 or parts[:3] != ["", "nix", "store"] or any(part in {"", ".", ".."} for part in parts[3:]):
        raise ValueError("invalid immutable patch path")
    return store_path("/".join(parts[:4]))


def realize_patch_inputs(derivations, source_roots):
    # Substituting a runtime closure does not fetch its build-time patches.
    # Resolve only missing patch outputs, never entire package build inputs.
    missing = {str(p) for drv in derivations.values() for p in patches(drv) if not Path(p).is_file()}
    if not missing:
        return
    roots = {patch: patch_store_root(patch) for patch in missing}
    # Literal Nixpkgs patches are inputSrcs, not derivation outputs. Recreate
    # their exact store paths from the locked source and verify Nix's identity.
    names = {Path(p).name[33:] for p in missing if p == roots[p]}
    candidates = {name: [] for name in names}
    for root in source_roots:
        for directory, _, files in os.walk(root):
            for name in names.intersection(files):
                candidates[name].append(Path(directory) / name)
    for patch in sorted(missing):
        if patch != roots[patch]:
            continue
        name = Path(patch).name[33:]
        for candidate in sorted(candidates[name]):
            if candidate.is_file():
                added = subprocess.check_output(["nix", "store", "add-file", "--name", name, str(candidate)], text=True).strip()
                if added == patch:
                    missing.remove(patch)
                    break
    if not missing:
        return
    inputs = sorted({p for drv in derivations.values() for p in input_derivations(drv)})
    producers = {}
    missing_roots = {roots[patch] for patch in missing}
    for start in range(0, len(inputs), 64):
        records = read_derivations(inputs[start:start + 64])
        for path, record in records.items():
            for output, info in record["outputs"].items():
                produced = output_path(record, output, info)
                if produced in missing_roots:
                    producers[produced] = path + "^" + output
    if missing_roots - producers.keys():
        raise ValueError("missing immutable patch producer metadata")
    subprocess.run(["nix", "build", "--no-link", *sorted(set(producers.values()))], check=True)
    # A patch may be a file within a fetched immutable source output. Realize
    # that exact producer once, then bind every requested file to its root.
    for patch in missing:
        if not Path(patch).is_file() or not Path(patch).resolve().is_relative_to(Path(roots[patch]).resolve()):
            raise ValueError("missing or escaping immutable patch file")


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
    derivations = read_derivations(drvs)
    context = json.loads(context_path.read_text())
    realize_patch_inputs(derivations, context["packageSourceRoots"])
    result = enrich(system, json.loads(supply_path.read_text()), context, derivations)
    system_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
