# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
from datetime import date
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch as mock_patch
from unittest.mock import mock_open


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / f"nix/automation/security-{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


inventory, normalizer, verdict = (module(name) for name in ["inventory", "normalize", "verdict"])


def reject(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError("accepted invalid security input")


drv_path = "/nix/store/" + "a" * 32 + "-fixture.drv"
producer_path = "/nix/store/" + "b" * 32 + "-patch.drv"
out_path = "/nix/store/" + "c" * 32 + "-fixture"
patch_path = "/nix/store/" + "d" * 32 + "-CVE-fixture.patch"
legacy = {"env": {"__json": json.dumps({"pname": "openssl", "version": "3.5.9", "patches": []}), "out": out_path},
          "outputs": {"out": {"path": out_path}}, "inputDrvs": {producer_path: ["out"]}}
modern = {"version": 4, "env": {"out": out_path},
          "structuredAttrs": {"pname": "openssl", "version": "3.5.9", "patches": []},
          "outputs": {"out": {"path": Path(out_path).name}},
          "inputs": {"drvs": {Path(producer_path).name: {"outputs": ["out"]}}, "srcs": []}}
for document in [{drv_path: legacy}, {"version": 4, "derivations": {Path(drv_path).name: modern}}]:
    decoded = inventory.decode_derivations(document)
    assert list(decoded) == [drv_path]
    record = decoded[drv_path]
    assert inventory.attributes(record)["version"] == "3.5.9"
    assert inventory.input_derivations(record) == [producer_path]
    assert inventory.output_path(record, "out", record["outputs"]["out"]) == out_path

for invalid in [[], {"version": 4}, {"version": 5, "derivations": {}},
                {"version": True, "derivations": {}}, {"version": 4, "derivations": []},
                {"version": 4, "derivations": {drv_path: legacy}},
                {drv_path: 4}, {"../escape.drv": legacy},
                {drv_path: {**modern, "version": 5}},
                {drv_path: {**modern, "inputs": {}}},
                {drv_path: {**modern, "structuredAttrs": []}},
                {drv_path: {**modern, "outputs": {"out": 3}}},
                {drv_path: {**legacy, "env": []}},
                {drv_path: {**legacy, "env": {"__json": 4}}},
                {drv_path: {"outputs": {}}},
                {drv_path: legacy, Path(drv_path).name: modern}]:
    reject(lambda: inventory.decode_derivations(invalid))
reject(lambda: inventory.patches({"env": {"__json": '{"patches":42}'}}))
reject(lambda: inventory.output_path(modern, "out", {"path": patch_path}))

# Both patch producer queries and their results must accept modern JSON,
# including fixed outputs whose specification no longer contains a path.
for producer_output in [{"path": Path(patch_path).name}, {"method": "flat", "hash": "sha256-fixture"}]:
    consumer = deepcopy(modern)
    consumer["structuredAttrs"]["patches"] = [patch_path]
    producer = {"version": 4, "env": {"out": patch_path}, "outputs": {"out": producer_output},
                "inputs": {"drvs": {}, "srcs": []}}
    response = json.dumps({"version": 4, "derivations": {Path(producer_path).name: producer}}).encode()
    realized = [False]
    with mock_patch.object(inventory.subprocess, "check_output", return_value=response) as query, \
            mock_patch.object(inventory.Path, "is_file", autospec=True, side_effect=lambda path: realized[0]), \
            mock_patch.object(inventory.subprocess, "run", side_effect=lambda *args, **kwargs: realized.__setitem__(0, True)) as build:
        inventory.realize_patch_inputs({drv_path: consumer}, [])
    query.assert_called_once_with(["nix", "derivation", "show", producer_path])
    build.assert_called_once_with(["nix", "build", "--no-link", producer_path + "^out"], check=True)

# Fetched source trees contain patches beneath their output root. Query and
# realize only that declared producer, preserving both individual file paths.
patch_root = "/nix/store/" + "d" * 32 + "-source"
nested_patches = [patch_root + "/debian/patches/CVE-fixture.patch", patch_root + "/debian/patches/second.patch"]
consumer = deepcopy(modern)
consumer["structuredAttrs"]["patches"] = nested_patches
producer = {"version": 4, "env": {"out": patch_root}, "outputs": {"out": {"method": "nar", "hash": "sha256-fixture"}},
            "inputs": {"drvs": {}, "srcs": []}}
response = json.dumps({"version": 4, "derivations": {Path(producer_path).name: producer}}).encode()
realized = [False]
with mock_patch.object(inventory.subprocess, "check_output", return_value=response) as query, \
        mock_patch.object(inventory.Path, "is_file", autospec=True, side_effect=lambda path: realized[0]), \
        mock_patch.object(inventory.subprocess, "run", side_effect=lambda *args, **kwargs: realized.__setitem__(0, True)) as build:
    inventory.realize_patch_inputs({drv_path: consumer}, [])
query.assert_called_once_with(["nix", "derivation", "show", producer_path])
build.assert_called_once_with(["nix", "build", "--no-link", producer_path + "^out"], check=True)
assert inventory.patches(consumer) == nested_patches

# Other declared build dependencies may be inspected for provenance, but must
# not be realized merely because a patch source needs recovery.
unused_producer_path = "/nix/store/" + "f" * 32 + "-build-tool.drv"
extra_consumer = deepcopy(consumer)
extra_consumer["inputs"]["drvs"][Path(unused_producer_path).name] = {"outputs": ["out"]}
extra_records = {Path(producer_path).name: producer, Path(unused_producer_path).name: {**producer, "env": {"out": out_path}}}
extra_response = json.dumps({"version": 4, "derivations": extra_records}).encode()
realized = [False]
with mock_patch.object(inventory.subprocess, "check_output", return_value=extra_response), \
        mock_patch.object(inventory.Path, "is_file", autospec=True, side_effect=lambda path: realized[0]), \
        mock_patch.object(inventory.subprocess, "run", side_effect=lambda *args, **kwargs: realized.__setitem__(0, True)) as build:
    inventory.realize_patch_inputs({drv_path: extra_consumer}, [])
build.assert_called_once_with(["nix", "build", "--no-link", producer_path + "^out"], check=True)

# A similarly named but different immutable output cannot supply a patch.
unrelated = deepcopy(producer)
unrelated["env"]["out"] = out_path
unrelated_response = json.dumps({"version": 4, "derivations": {Path(producer_path).name: unrelated}}).encode()
with mock_patch.object(inventory.subprocess, "check_output", return_value=unrelated_response), \
        mock_patch.object(inventory.Path, "is_file", return_value=False), \
        mock_patch.object(inventory.subprocess, "run") as build:
    reject(lambda: inventory.realize_patch_inputs({drv_path: consumer}, []))
build.assert_not_called()

# Successful realization must provide every requested file, and a symlink
# cannot escape the declared output tree to another immutable or mutable root.
for escape in [False, True]:
    realized = [False]
    def file_exists(path):
        return realized[0] and (escape or str(path) != nested_patches[1])
    def resolved(path):
        return Path("/tmp/escaping-patch") if escape and str(path) == nested_patches[1] else path
    with mock_patch.object(inventory.subprocess, "check_output", return_value=response), \
            mock_patch.object(inventory.Path, "is_file", autospec=True, side_effect=file_exists), \
            mock_patch.object(inventory.Path, "resolve", autospec=True, side_effect=resolved), \
            mock_patch.object(inventory.subprocess, "run", side_effect=lambda *args, **kwargs: realized.__setitem__(0, True)) as build:
        reject(lambda: inventory.realize_patch_inputs({drv_path: consumer}, []))
    build.assert_called_once_with(["nix", "build", "--no-link", producer_path + "^out"], check=True)

for unsafe in [patch_root + "/../outside.patch", patch_root + "/./patch", patch_root + "//patch", "/tmp/patch"]:
    unsafe_consumer = deepcopy(consumer)
    unsafe_consumer["structuredAttrs"]["patches"] = [unsafe]
    with mock_patch.object(inventory.Path, "is_file", return_value=False), \
            mock_patch.object(inventory.subprocess, "check_output") as query, \
            mock_patch.object(inventory.subprocess, "run") as build:
        reject(lambda: inventory.realize_patch_inputs({drv_path: unsafe_consumer}, []))
    query.assert_not_called()
    build.assert_not_called()

with mock_patch.object(inventory.subprocess, "check_output", return_value=b'{"version":4,"derivations":{}}'):
    reject(lambda: inventory.read_derivations([drv_path]))

batch_paths = [drv_path.removesuffix(".drv") + f"-{index}.drv" for index in range(67)]
def batched_response(command):
    return json.dumps({"version": 4, "derivations": {Path(path).name: modern for path in command[3:]}}).encode()
with mock_patch.object(inventory.subprocess, "check_output", side_effect=batched_response) as query:
    assert set(inventory.read_derivations(batch_paths)) == set(batch_paths)
assert [call.args[0][3:] for call in query.call_args_list] == [batch_paths[:64], batch_paths[64:]]

with tempfile.TemporaryDirectory() as temporary:
    patch = Path(temporary) / "CVE-fixture.patch"
    patch.write_text("verified patch\n")
    components = [{"type": "library", "name": "openssl-1.0.1", "version": "", "bom-ref": ref,
                   "properties": [{"name": "nix:drv_path", "value": ref}]} for ref in ["patched.drv", "unpatched.drv"]]
    system = {"bomFormat": "CycloneDX", "components": components,
              "metadata": {"component": {"bom-ref": "root"}},
              "dependencies": [{"ref": "root", "dependsOn": ["patched.drv", "unpatched.drv"]}]}
    supply = {"bomFormat": "CycloneDX", "components": [{"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15", "bom-ref": "npm:lodash"}],
              "metadata": {"component": {"bom-ref": "npm:lodash"}}, "dependencies": []}
    drvs = {ref: {"env": {"pname": "openssl", "version": "1.0.1", "patches": str(patch) if ref == "patched.drv" else ""}} for ref in ["patched.drv", "unpatched.drv"]}
    result = inventory.enrich(deepcopy(system), supply, {"platform": "x86_64-linux"}, drvs)
    assert result["components"][0]["purl"] == "pkg:nix/openssl@1.0.1"
    reject(lambda: inventory.enrich(deepcopy(system), {**supply, "components": []}, {}, drvs))
    report = {"matches": [{"vulnerability": {"id": "CVE-fixture", "severity": "High", "namespace": "nvd:cpe"},
                           "artifact": {"id": ref, "name": "openssl", "version": "1.0.1", "purl": "pkg:nix/openssl@1.0.1"},
                           "matchDetails": [{"type": "cpe-match"}]} for ref in ["patched.drv", "unpatched.drv"]]}
    findings = normalizer.normalize(report, result, {"version": "fixture"})
    assert len(findings) == 2 and findings[0]["identity"] != findings[1]["identity"]
    patched = next(f for f in findings if f["binding"]["derivation"] == "patched.drv")
    unpatched = next(f for f in findings if f["binding"]["derivation"] == "unpatched.drv")
    accepted = {k: patched[k] for k in verdict.KEYS}
    accepted.update(kind="fixed", owner="operator", reason="verified patch", evidence=["https://example.invalid/commit"], created="2026-10-12", expires="2026-10-30")
    policy = {"schema_version": 2, "mode": "enforce", "dispositions": [accepted], "exceptions": []}
    today = date(2026, 10, 12)
    assert verdict.evaluate(findings, policy, today) == [unpatched]
    assert not verdict.evaluate([patched], policy, today)
    for modification in ["patch", "context", "scanner", "advisory"]:
        changed_drvs, context, scanner = deepcopy(drvs), {"platform": "x86_64-linux"}, {"version": "fixture"}
        changed_report = deepcopy(report)
        if modification == "patch":
            changed_drvs["patched.drv"]["env"]["patches"] = ""
        elif modification == "context":
            context["capability"] = "new"
        elif modification == "scanner":
            scanner["version"] = "changed"
        else:
            for match in changed_report["matches"]:
                match["vulnerability"]["description"] = "Revised advisory applicability"
        changed = normalizer.normalize(changed_report, inventory.enrich(deepcopy(system), supply, context, changed_drvs), scanner)
        assert len(verdict.evaluate(changed, policy, today)) == 2
    for severity in ["critical", "unknown"]:
        assert verdict.evaluate([{**patched, "severity": severity}], policy, today)
    reject(lambda: verdict.evaluate(findings, policy, date(2026, 11, 1)))
    reject(lambda: verdict.evaluate(findings, {**policy, "baseline": []}, today))
    invalid = deepcopy(report)
    invalid["matches"][0]["artifact"]["id"] = "unknown"
    reject(lambda: normalizer.normalize(invalid, result, {"version": "fixture"}))
    missing = deepcopy(drvs)
    del missing["patched.drv"]
    reject(lambda: inventory.enrich(deepcopy(system), supply, {}, missing))

    # Exercise the complete CLI entry point, not just the envelope decoder.
    modern_system = deepcopy(system)
    # The raw serializer groups one component per derivation; two components
    # claiming the exact same output are invalid, not a modern-CLI fixture.
    modern_system["components"] = modern_system["components"][:1]
    modern_system["dependencies"][0]["dependsOn"] = [modern_system["components"][0]["bom-ref"]]
    for component in modern_system["components"]:
        component["properties"][0]["value"] = drv_path
        component["properties"].append({"name": "nix:output_path", "value": out_path})
    cli_record = deepcopy(modern)
    cli_record["structuredAttrs"]["patches"] = [str(patch)]
    response = json.dumps({"version": 4, "derivations": {Path(drv_path).name: cli_record}}).encode()
    system_file, supply_file, context_file = [Path(temporary) / name for name in ("system.json", "supply.json", "context.json")]
    system_file.write_text(json.dumps(modern_system))
    supply_file.write_text(json.dumps(supply))
    context_file.write_text(json.dumps({"packageSourceRoots": [], "distributionRoots": [out_path]}))
    def cli_query(command):
        if command[:3] == ["nix", "path-info", "--json"]:
            return json.dumps({out_path: {"narHash": "sha256-" + "A" * 43 + "="}}).encode()
        return response
    with mock_patch.object(inventory.sys, "argv", ["inventory", str(system_file), str(supply_file), str(context_file)]), \
            mock_patch.object(inventory.subprocess, "check_output", side_effect=cli_query) as query:
        inventory.main()
    assert query.call_count == 3
    query.assert_any_call(["nix", "derivation", "show", drv_path])
    enriched = json.loads(system_file.read_text())
    assert enriched["components"][0]["purl"] == "pkg:nix/openssl@3.5.9"
    props = inventory.properties(enriched["components"][0])
    assert props["maestro:outputName"] == "out"
    assert json.loads(props["maestro:patches"])[0]["path"] == str(patch)
print("Security identity, inventory, drift, expiry and severity fixtures passed")

# Match the real sbomnix representation: one drv component advertises every
# env.outputs path, including unshipped/unrealized dev/man outputs.
bin_path = out_path + "-bin"
unshipped = out_path + "-dev"
multi = {"bom-ref": "openssl-drv", "type": "library", "name": "openssl", "version": "3.5.9",
         "properties": [{"name": "nix:drv_path", "value": drv_path}] +
                       [{"name": "nix:output_path", "value": p} for p in [out_path, bin_path, unshipped]]}
graph = {"components": [deepcopy(multi)], "metadata": {"component": {"bom-ref": "root"}},
         "dependencies": [{"ref": "root", "dependsOn": ["openssl-drv"]},
                          {"ref": "openssl-drv", "dependsOn": ["root"]}]}
inventory.expand_runtime_outputs(graph, {out_path: {}, bin_path: {}})
assert len(graph["components"]) == 2
refs = {c["bom-ref"] for c in graph["components"]}
assert len(refs) == 2 and "openssl-drv" not in refs
assert {inventory.properties(c)["nix:output_path"] for c in graph["components"]} == {out_path, bin_path}
assert next(d for d in graph["dependencies"] if d["ref"] == "root")["dependsOn"] == sorted(refs)
assert all(d["dependsOn"] == ["root"] for d in graph["dependencies"] if d["ref"] in refs)
# Metadata can itself represent a multi-output producer. Every old graph alias
# must map to all actual outputs, with exactly one selected metadata component.
metadata_graph = {"components": [], "metadata": {"component": deepcopy(multi)},
                  "dependencies": [{"ref": "openssl-drv", "dependsOn": ["openssl-drv"]}]}
inventory.expand_runtime_outputs(metadata_graph, {out_path: {}, bin_path: {}})
all_refs = {metadata_graph["metadata"]["component"]["bom-ref"], metadata_graph["components"][0]["bom-ref"]}
assert len(all_refs) == 2
assert {d["ref"] for d in metadata_graph["dependencies"]} == all_refs
assert all(set(d["dependsOn"]) == all_refs for d in metadata_graph["dependencies"])
metadata_graph["bomFormat"] = "CycloneDX"
native_record = {"env": {"pname": "openssl", "version": "3.5.9", "patches": [], "out": out_path, "bin": bin_path},
                 "outputs": {"out": {"path": out_path}, "bin": {"path": bin_path}}}
metadata_result = inventory.enrich(metadata_graph, supply, {}, {drv_path: native_record})
outputs = [metadata_result["metadata"]["component"], metadata_result["components"][0]]
assert {inventory.properties(c)["maestro:outputName"] for c in outputs} == {"out", "bin"}
assert all(c["purl"] == "pkg:nix/openssl@3.5.9" for c in outputs)
union = {"bomFormat": "CycloneDX", "components": [deepcopy(multi)],
         "metadata": {"component": {"bom-ref": "union", "name": "union", "version": "", "properties": [
             {"name": "nix:drv_path", "value": producer_path}, {"name": "nix:output_path", "value": patch_path}]}},
         "dependencies": [{"ref": "union", "dependsOn": ["openssl-drv"]}]}
inventory.expand_runtime_outputs(union, {out_path: {}, bin_path: {}, patch_path: {}})
union_record = {"env": {"name": "distribution-inventory", "out": patch_path}, "outputs": {"out": {"path": patch_path}}}
assert inventory.enrich(union, supply, {}, {drv_path: native_record, producer_path: union_record})["metadata"]["component"]["type"] == "file"
for extra in [{"name": "nix:drv_path", "value": drv_path},
              {"name": "nix:drv_path", "value": producer_path},
              {"name": "nix:storePath", "value": patch_path},
              {"name": "nix:output_path", "value": out_path},
              {"name": "maestro:staticSource", "value": "true"}]:
    invalid = deepcopy(multi)
    invalid["properties"].append(extra)
    reject(lambda: inventory.expand_runtime_outputs({"components": [invalid], "dependencies": []}, {out_path: {}, bin_path: {}}))
reject(lambda: inventory.properties({"properties": [{"name": "nix:storePath", "value": out_path}] * 2}))

nar = "sha256-" + "A" * 43 + "="
record = {"narHash": nar}
with mock_patch.object(inventory.subprocess, "check_output", return_value=""), \
        mock_patch.object(inventory.Path, "is_symlink", return_value=False), \
        mock_patch.object(inventory.Path, "is_file", return_value=True), \
        mock_patch.object(inventory.Path, "open", mock_open(read_data=b'{"schema":1}')):
    source = inventory.static_source(patch_path, record)
    assert source["type"] == "file" and "purl" not in source and "version" not in source
    assert inventory.properties(source)["maestro:narHash"] == nar
    reject(lambda: inventory.static_source(patch_path, {**record, "deriver": drv_path}))
    reject(lambda: inventory.static_source(patch_path, {}))
for magic in [b"\x7fELF", b"MZxx", b"\x00asm", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
              b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
              b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"]:
    with mock_patch.object(inventory.subprocess, "check_output", return_value=""), \
            mock_patch.object(inventory.Path, "is_symlink", return_value=False), \
            mock_patch.object(inventory.Path, "is_file", return_value=True), \
            mock_patch.object(inventory.Path, "open", mock_open(read_data=magic)):
        reject(lambda: inventory.static_source(patch_path, record))
        # A represented type=file or fake version/purl is not negative proof.
        for claimed in [{"type": "file"}, {"type": "library", "version": "1", "purl": "pkg:nix/fake@1"}]:
            represented = {"components": [{"bom-ref": "unverified", "properties": [{"name": "nix:output_path", "value": patch_path}], **claimed}],
                           "metadata": {"component": {"bom-ref": "root"}}, "dependencies": []}
            with mock_patch.object(inventory.subprocess, "check_output", side_effect=[json.dumps({patch_path: record}).encode(), ""]):
                reject(lambda: inventory.bind_inventory_roots(represented, [{"storePath": patch_path, "narHash": nar}]))
for symlink, regular in [(True, True), (False, False)]:
    with mock_patch.object(inventory.subprocess, "check_output", return_value=""), \
            mock_patch.object(inventory.Path, "is_symlink", return_value=symlink), \
            mock_patch.object(inventory.Path, "is_file", return_value=regular):
        reject(lambda: inventory.static_source(patch_path, record))
with mock_patch.object(inventory.subprocess, "check_output", return_value=drv_path):
    reject(lambda: inventory.static_source(patch_path, record))
print("Actual-output expansion, graph aliases and strict immutable plain-file provenance fixtures passed")
