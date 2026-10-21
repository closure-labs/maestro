#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enrich the runtime SBOM using exact derivations, never guessed versions."""
import hashlib
from copy import deepcopy
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
    result = {}
    for prop in component.get("properties", []):
        name, value = prop["name"], prop["value"]
        if name in result and name != "nix:output_path":
            raise ValueError("duplicate singleton inventory property: " + name)
        result[name] = value
    return result


def expand_runtime_outputs(system, records):
    """sbomnix groups by derivation and advertises even unrealized outputs."""
    aliases, owners = {}, {}
    def expand(component):
        ref = component["bom-ref"]
        if ref in aliases:
            raise ValueError("duplicate raw component reference")
        props = properties(component)
        if "maestro:staticSource" in props:
            raise ValueError("raw inventory cannot assert validated static source provenance")
        paths = [store_path(p["value"]) for p in component.get("properties", []) if p["name"] == "nix:output_path"]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate advertised inventory output")
        if "nix:storePath" in props:
            path = store_path(props["nix:storePath"])
            if paths and set(paths) != {path}:
                raise ValueError("conflicting immutable component output identities")
            paths = [path]
        if not paths:
            aliases[ref] = [ref]
            return [component]
        actual = sorted(set(paths) & records.keys())
        result = []
        for path in actual:
            if path in owners:
                raise ValueError("runtime output belongs to multiple components")
            owners[path] = ref
            value = deepcopy(component)
            value["bom-ref"] = ref if len(actual) == 1 else "maestro:output:" + path
            value["properties"] = [p for p in value.get("properties", []) if p["name"] not in ("nix:output_path", "nix:storePath")]
            value["properties"].append({"name": "nix:output_path", "value": path})
            result.append(value)
        aliases[ref] = [value["bom-ref"] for value in result]
        return result
    expanded = [value for component in system["components"] for value in expand(component)]
    metadata = system.get("metadata", {}).get("component")
    if metadata:
        values = expand(metadata)
        if not values:
            raise ValueError("inventory metadata root is outside actual runtime closure")
        system["metadata"]["component"] = values[0]
        expanded.extend(values[1:])
    system["components"] = expanded
    dependencies = {}
    for entry in system.get("dependencies", []):
        for ref in aliases.get(entry["ref"], [entry["ref"]]):
            values = dependencies.setdefault(ref, set())
            for target in entry.get("dependsOn", []):
                values.update(aliases.get(target, [target]))
    system["dependencies"] = [{"ref": ref, "dependsOn": sorted(values)} for ref, values in sorted(dependencies.items())]


def static_source(path, record):
    """Literal source/data files are omitted by sbomnix, never native packages."""
    valid = subprocess.check_output(["nix-store", "--query", "--valid-derivers", path], text=True).strip()
    if valid or record.get("deriver") not in (None, "", "unknown-deriver"):
        raise ValueError("unrepresented runtime output has a native producer: " + path)
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ValueError("unrepresented runtime source is not a regular plain file: " + path)
    with source.open("rb") as stream:
        magic = stream.read(4)
    if magic[:2] == b"MZ" or magic in (b"\x7fELF", b"\x00asm", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        raise ValueError("unrepresented native code lacks package provenance: " + path)
    nar_hash = record.get("narHash")
    if not isinstance(nar_hash, str) or not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", nar_hash):
        raise ValueError("immutable source NAR evidence is missing")
    return {"type": "file", "name": source.name, "bom-ref": "maestro:source:" + path,
            "properties": [{"name": "nix:output_path", "value": path},
                           {"name": "maestro:staticSource", "value": "true"},
                           {"name": "maestro:narHash", "value": nar_hash}]}


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
    metadata = system.get("metadata", {}).get("component", {})
    native_components = [*system["components"]]
    if properties(metadata).get("nix:drv_path"):
        native_components.append(metadata)
    for component in native_components:
        props = properties(component)
        if props.get("maestro:staticSource") == "true":
            continue
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
        shipped = props.get("nix:output_path", props.get("nix:storePath"))
        outputs = [name for name, info in derivations[drv].get("outputs", {}).items()
                   if output_path(derivations[drv], name, info) == shipped]
        if shipped and len(outputs) != 1:
            raise ValueError("runtime component is not one exact derivation output")
        component.setdefault("properties", []).extend([
            {"name": "maestro:derivation", "value": drv},
            {"name": "maestro:source", "value": json.dumps(attrs.get("src"), sort_keys=True)},
            {"name": "maestro:patches", "value": json.dumps(patch_records, sort_keys=True)},
            {"name": "maestro:derivationDigest", "value": digest(derivations[drv])},
        ])
        if outputs:
            component["properties"].append({"name": "maestro:outputName", "value": outputs[0]})
    merge_supply_inventory(system, supply)
    system.setdefault("properties", []).extend([
        {"name": "maestro:inventoryVersion", "value": "2"},
        {"name": "maestro:runtimeContext", "value": json.dumps(context, sort_keys=True)},
        {"name": "maestro:runtimeContextDigest", "value": digest(context)},
        {"name": "maestro:installedNpmCount", "value": str(len(npm))},
    ])
    return system


def merge_supply_inventory(system, supply):
    """Alias imported native outputs to independently validated exact producers."""
    primary = [*system["components"], system.get("metadata", {}).get("component", {})]
    refs, by_path = set(), {}
    for component in primary:
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref or ref in refs:
            raise ValueError("duplicate or missing primary component identity")
        refs.add(ref)
        props = properties(component)
        path = props.get("nix:output_path", props.get("nix:storePath"))
        if path:
            by_path.setdefault(store_path(path), []).append(component)
    root = system.get("metadata", {}).get("component", {}).get("bom-ref")
    metadata = supply.get("metadata", {}).get("component", {})
    imported = list(supply["components"])
    source_refs = {}
    for component in imported:
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref or ref in source_refs or ref in refs:
            raise ValueError("colliding supply component identity")
        source_refs[ref] = component
    xo_root = metadata.get("bom-ref")
    if not root or not isinstance(xo_root, str) or not xo_root:
        raise ValueError("missing inventory root identity")
    if xo_root in source_refs:
        if any(metadata[key] != source_refs[xo_root].get(key) for key in ("name", "version", "purl", "properties") if key in metadata):
            raise ValueError("supply metadata conflicts with its component")
    elif metadata.get("purl", "").startswith("pkg:nix/") and xo_root not in refs:
        imported.append(metadata)
        source_refs[xo_root] = metadata
    else:
        raise ValueError("supply metadata references an unknown component")
    aliases, receipts = {}, {}
    for component in imported:
        purl = component.get("purl")
        if not isinstance(purl, str) or not purl or (component.get("type") == "library" and not component.get("version") and not purl.startswith("pkg:github/")):
            raise ValueError("unscannable XO library component")
        ref = component["bom-ref"]
        if not purl.startswith("pkg:nix/"):
            aliases[ref] = ref
            system["components"].append(deepcopy(component))
            refs.add(ref)
            continue
        props = properties(component)
        paths = [store_path(prop["value"]) for prop in component.get("properties", [])
                 if prop["name"] in ("nix:output_path", "nix:storePath")]
        if not paths or len(set(paths)) != 1:
            raise ValueError("native supply component lacks one exact immutable output")
        path = paths[0]
        candidates = by_path.get(path, [])
        if len(candidates) != 1:
            raise ValueError("native supply output has no unique validated primary component: " + path)
        canonical = candidates[0]
        bound = properties(canonical)
        name, version = canonical.get("name"), canonical.get("version")
        output, drv = bound.get("maestro:outputName"), bound.get("maestro:derivation")
        if (not all(isinstance(value, str) and value for value in (name, version, output, drv))
                or canonical.get("purl") != "pkg:nix/" + quote(name, safe="") + "@" + quote(version, safe="")
                or bound.get("nix:drv_path") != drv or not bound.get("maestro:derivationDigest")):
            raise ValueError("native supply primary lacks validated package/output provenance")
        legacy_version = component.get("version")
        # Only the observed legacy serializer's exact output suffix is allowed
        # as noncanonical evidence. It never becomes a scanned package version.
        if (component.get("name") != name or legacy_version not in (version, version + "-" + output)
                or purl != "pkg:nix/" + quote(name, safe="") + "@" + quote(legacy_version, safe="")):
            raise ValueError("native supply identity conflicts with its exact primary output")
        if (any(props[key] != output for key in ("maestro:outputName", "xo-nixpkg:outputName") if key in props)
                or any(props[key] != drv for key in ("maestro:derivation", "nix:derivation", "nix:drv_path") if key in props)
                or ("nix:storeHash" in props and props["nix:storeHash"] != Path(path).name[:32])):
            raise ValueError("native supply provenance conflicts with its exact primary output")
        aliases[ref] = canonical["bom-ref"]
        receipts.setdefault(canonical["bom-ref"], []).append({"component": deepcopy(component)})
    for component in primary:
        if component["bom-ref"] in receipts:
            component.setdefault("properties", []).append({"name": "maestro:supplyNativeAliases",
                "value": json.dumps(receipts[component["bom-ref"]], sort_keys=True)})
    dependencies = {}
    for source, entries in ((False, system.get("dependencies", [])), (True, supply.get("dependencies", []))):
        for entry in entries:
            ref, targets = entry.get("ref"), entry.get("dependsOn", [])
            allowed = source_refs.keys() if source else refs
            if not isinstance(ref, str) or ref not in allowed or not isinstance(targets, list) or any(not isinstance(target, str) or target not in allowed for target in targets):
                raise ValueError("dependency references an unknown component")
            target_ref = aliases[ref] if source else ref
            dependencies.setdefault(target_ref, set()).update(aliases[target] if source else target for target in targets)
    dependencies.setdefault(root, set()).add(aliases[xo_root])
    system["dependencies"] = [{"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(dependencies.items())]
    system.setdefault("properties", []).append({"name": "maestro:supplyInventoryDigest", "value": digest(supply)})


def bind_structural_inventory_metadata(system, expected, records):
    metadata = system.get("metadata", {}).get("component")
    if not metadata:
        return
    props = properties(metadata)
    advertised = [store_path(prop["value"]) for prop in metadata.get("properties", [])
                  if prop["name"] == "nix:output_path"]
    if "nix:storePath" in props:
        path = store_path(props["nix:storePath"])
        if advertised and set(advertised) != {path}:
            raise ValueError("conflicting structural inventory output identities")
        if not advertised:
            advertised = [path]
    # Ordinary runtime metadata still follows multi-output expansion. Only an
    # entirely external graph parent is eligible for this structural proof.
    name = "maestro-distribution-inventory"
    if not advertised or set(advertised) & records.keys():
        if metadata.get("name") == name:
            raise ValueError("structural inventory parent must be outside publication subjects")
        return
    if (len(advertised) != 1 or metadata.get("name") != name
            or metadata.get("version") not in (None, "")
            or metadata.get("purl") not in (None, "", "pkg:nix/" + name)
            or metadata.get("cpe") not in (None, "", f"cpe:2.3:a:{name}:{name}::*:*:*:*:*:*:*")
            or not isinstance(metadata.get("bom-ref"), str) or not metadata["bom-ref"]):
        raise ValueError("external inventory metadata is not the known structural parent")
    path = advertised[0]
    if not path.endswith("-" + name):
        raise ValueError("structural inventory output name differs")
    drv = store_path(props.get("nix:drv_path"))
    if not drv.endswith(".drv"):
        raise ValueError("structural inventory producer is invalid")
    directory = Path(path)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("structural inventory parent is not a real directory")
    entries = list(directory.iterdir())
    if len(entries) != len(expected) or any(not entry.is_symlink() for entry in entries):
        raise ValueError("structural inventory entries are not exactly subject symlinks")
    targets = [os.readlink(entry) for entry in entries]
    if (any(target != store_path(target) for target in targets)
            or len(set(targets)) != len(targets) or set(targets) != expected.keys()):
        raise ValueError("structural inventory links differ from publication subjects")
    document = json.loads(subprocess.check_output(["nix", "path-info", "--json", path]))
    if isinstance(document, list):
        if len(document) != 1 or not isinstance(document[0], dict) or document[0].get("path") != path:
            raise ValueError("structural inventory Nix metadata differs")
        record = document[0]
    elif isinstance(document, dict) and set(document) == {path}:
        record = document[path]
    else:
        raise ValueError("structural inventory Nix metadata differs")
    if not isinstance(record, dict) or record.get("path", path) != path or record.get("deriver") != drv:
        raise ValueError("structural inventory producer metadata differs")
    references = record.get("references")
    if (not isinstance(references, list) or len(references) != len(expected)
            or any(reference != store_path(reference) for reference in references)
            or set(references) != expected.keys()):
        raise ValueError("structural inventory references differ from publication subjects")
    nar_hash = record.get("narHash")
    if not isinstance(nar_hash, str) or not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", nar_hash):
        raise ValueError("structural inventory NAR identity is invalid")
    actual_nar = subprocess.check_output(["nix", "hash", "path", "--type", "sha256", "--sri", path], text=True).strip()
    if actual_nar != nar_hash:
        raise ValueError("structural inventory content differs from its NAR identity")
    producer = read_derivations([drv])[drv]
    attrs = attributes(producer)
    if (attrs.get("name") != name or attrs.get("pname") not in (None, "", name)
            or attrs.get("version") not in (None, "") or set(producer["outputs"]) != {"out"}
            or output_path(producer, "out", producer["outputs"]["out"]) != path):
        raise ValueError("structural inventory derivation does not declare the known parent")
    receipt = {"schema": 1, "storePath": path, "narHash": nar_hash, "derivation": drv,
               "roots": [{"storePath": root, "narHash": expected[root]} for root in sorted(expected)]}
    ref = metadata["bom-ref"]
    metadata.clear()
    metadata.update({"type": "file", "name": name, "bom-ref": ref,
                     "properties": [{"name": "maestro:inventoryAggregate", "value": json.dumps(receipt, sort_keys=True)}]})


def bind_inventory_roots(system, roots, qualification=None):
    if not isinstance(roots, list) or not roots:
        raise ValueError("publication inventory roots are required")
    expected = {}
    for subject in roots:
        if not isinstance(subject, dict) or set(subject) != {"storePath", "narHash"}:
            raise ValueError("invalid publication inventory subject")
        path = store_path(subject["storePath"])
        if path in expected or not isinstance(subject["narHash"], str) or not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", subject["narHash"]):
            raise ValueError("invalid or duplicate publication NAR identity")
        expected[path] = subject["narHash"]
    document = json.loads(subprocess.check_output(["nix", "path-info", "--json", "--recursive", *sorted(expected)]))
    if isinstance(document, list):
        records = {record["path"]: record for record in document}
        if len(records) != len(document):
            raise ValueError("duplicate closure identity")
    elif isinstance(document, dict):
        records = document
    else:
        raise ValueError("invalid recursive Nix closure metadata")
    for path, nar_hash in expected.items():
        if records.get(path, {}).get("narHash") != nar_hash:
            raise ValueError("publication root differs from expected NAR identity")
    if qualification is not None and not set(qualification["roots"].values()) <= expected.keys():
        raise ValueError("installer qualification roots are absent from inventory subjects")
    for component in [*system["components"], system.get("metadata", {}).get("component", {})]:
        props = properties(component)
        if "maestro:inventoryAggregate" in props or "maestro:staticSource" in props:
            raise ValueError("raw inventory cannot assert validated structural provenance")
    bind_structural_inventory_metadata(system, expected, records)
    expand_runtime_outputs(system, records)
    for component in [*system["components"], system.get("metadata", {}).get("component", {})]:
        props = properties(component)
        path = props.get("nix:output_path", props.get("nix:storePath"))
        if path and not props.get("nix:drv_path"):
            source = static_source(path, records[path])
            source["bom-ref"] = component["bom-ref"]
            component.clear()
            component.update(source)
    represented = set()
    for component in [*system["components"], system.get("metadata", {}).get("component", {})]:
        props = properties(component)
        path = props.get("nix:output_path", props.get("nix:storePath"))
        if path:
            represented.add(store_path(path))
    missing = sorted(records.keys() - represented)
    # Keep the failure diagnostic bounded. Never turn absent native packages
    # into guessed file identities, or fetch/build advertised unshipped outputs.
    for path in missing:
        try:
            component = static_source(path, records[path])
        except ValueError as error:
            raise ValueError("system inventory omits publication closure outputs: " +
                             json.dumps(missing[:20]) + (" (truncated)" if len(missing) > 20 else "")) from error
        system["components"].append(component)
        root = system.get("metadata", {}).get("component", {}).get("bom-ref")
        if not root:
            raise ValueError("static source evidence requires an inventory root")
        dependencies = next((entry for entry in system.setdefault("dependencies", []) if entry["ref"] == root), None)
        if dependencies is None:
            dependencies = {"ref": root, "dependsOn": []}
            system["dependencies"].append(dependencies)
        dependencies.setdefault("dependsOn", []).append(component["bom-ref"])
    system.setdefault("properties", []).append({"name": "maestro:inventoryRoots", "value": json.dumps(roots, sort_keys=True)})


def main():
    system_path, supply_path, context_path = map(Path, sys.argv[1:])
    system = json.loads(system_path.read_text())
    context = json.loads(context_path.read_text())
    qualification = context.get("installerQualification")
    if qualification is not None:
        if (qualification.get("schema") != 1 or not isinstance(qualification.get("roots"), dict)
                or not qualification["roots"] or not isinstance(qualification.get("bindings"), list)
                or not qualification["bindings"] or not isinstance(qualification.get("policy"), dict)):
            raise ValueError("incomplete installer qualification manifest")
        store_path(qualification["iso"])
        declared = set(qualification["roots"].values())
        if qualification.get("system") not in declared:
            raise ValueError("installer system absent from qualification roots")
        for binding in qualification["bindings"]:
            if binding.get("root") not in declared or not (binding.get("source") == binding["root"] or binding.get("source", "").startswith(binding["root"] + "/")):
                raise ValueError("installer content lacks retained native origin")
    roots_path = os.environ.get("DECISION_ROOTS_JSON")
    if roots_path:
        roots = json.loads(Path(roots_path).read_text())
    else:
        distribution = context.get("distributionRoots")
        if not isinstance(distribution, list) or not distribution or any(not isinstance(path, str) for path in distribution):
            raise ValueError("complete publication distributionRoots are required")
        paths = sorted({store_path(path) for path in distribution})
        records = json.loads(subprocess.check_output(["nix", "path-info", "--json", *paths]))
        if isinstance(records, list):
            records = {record["path"]: record for record in records}
        if not isinstance(records, dict) or records.keys() != set(paths):
            raise ValueError("publication root metadata does not match expected outputs")
        roots = [{"storePath": path, "narHash": records[path]["narHash"]} for path in paths]
    bind_inventory_roots(system, roots, qualification)
    if qualification is not None:
        system.setdefault("properties", []).append({"name": "maestro:qualificationCoverage", "value": json.dumps({
            "contract": "maestro-distribution-v2", "manifest": qualification}, sort_keys=True)})
    candidates = [*system["components"], system.get("metadata", {}).get("component", {})]
    drvs = sorted({properties(c)["nix:drv_path"] for c in candidates if properties(c).get("nix:drv_path") and properties(c).get("maestro:staticSource") != "true"})
    derivations = read_derivations(drvs)
    realize_patch_inputs(derivations, context["packageSourceRoots"])
    raw_inventory_inputs={'system':digest(system),'supply':digest(json.loads(supply_path.read_text())),
                          'generator':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    result = enrich(system, json.loads(supply_path.read_text()), context, derivations)
    system_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    sys.path.insert(0,os.environ.get('MAESTRO_FINGERPRINTS_CORE',str(Path(__file__).with_name('decisions'))))
    import fingerprints
    keys=fingerprints.bindings(raw_inventory_inputs,{'normalizer':context.get('normalizerDigest','unbound')},{key:context[key] for key in ('platform','runtime','installerQualification') if key in context},{}, {})
    system_path.with_name('inventory-fingerprints.json').write_text(json.dumps(keys,sort_keys=True)+'\n')


if __name__ == "__main__":
    main()
