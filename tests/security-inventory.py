# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
from datetime import date
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch as mock_patch


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
    with mock_patch.object(inventory.subprocess, "check_output", return_value=response) as query, \
            mock_patch.object(inventory.subprocess, "run") as build:
        inventory.realize_patch_inputs({drv_path: consumer}, [])
    query.assert_called_once_with(["nix", "derivation", "show", producer_path])
    build.assert_called_once_with(["nix", "build", "--no-link", producer_path + "^out"], check=True)

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
    for component in modern_system["components"]:
        component["properties"][0]["value"] = drv_path
    cli_record = deepcopy(modern)
    cli_record["structuredAttrs"]["patches"] = [str(patch)]
    response = json.dumps({"version": 4, "derivations": {Path(drv_path).name: cli_record}}).encode()
    system_file, supply_file, context_file = [Path(temporary) / name for name in ("system.json", "supply.json", "context.json")]
    system_file.write_text(json.dumps(modern_system))
    supply_file.write_text(json.dumps(supply))
    context_file.write_text(json.dumps({"packageSourceRoots": []}))
    with mock_patch.object(inventory.sys, "argv", ["inventory", str(system_file), str(supply_file), str(context_file)]), \
            mock_patch.object(inventory.subprocess, "check_output", return_value=response) as query:
        inventory.main()
    query.assert_called_once_with(["nix", "derivation", "show", drv_path])
    enriched = json.loads(system_file.read_text())
    assert enriched["components"][0]["purl"] == "pkg:nix/openssl@3.5.9"
    props = inventory.properties(enriched["components"][0])
    assert json.loads(props["maestro:patches"])[0]["path"] == str(patch)
print("Security identity, inventory, drift, expiry and severity fixtures passed")
