# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
from datetime import date
import importlib.util
from pathlib import Path
import tempfile


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
    accepted = {k: findings[0][k] for k in verdict.KEYS}
    accepted.update(kind="fixed", owner="operator", reason="verified patch", evidence=["https://example.invalid/commit"], created="2026-10-12", expires="2026-10-30")
    policy = {"schema_version": 2, "mode": "enforce", "dispositions": [accepted], "exceptions": []}
    today = date(2026, 10, 12)
    assert verdict.evaluate(findings, policy, today) == [findings[1]]
    assert not verdict.evaluate([findings[0]], policy, today)
    for modification in ["patch", "context", "scanner"]:
        changed_drvs, context, scanner = deepcopy(drvs), {"platform": "x86_64-linux"}, {"version": "fixture"}
        if modification == "patch":
            changed_drvs["patched.drv"]["env"]["patches"] = ""
        elif modification == "context":
            context["capability"] = "new"
        else:
            scanner["version"] = "changed"
        changed = normalizer.normalize(report, inventory.enrich(deepcopy(system), supply, context, changed_drvs), scanner)
        assert len(verdict.evaluate(changed, policy, today)) == 2
    for severity in ["critical", "unknown"]:
        assert verdict.evaluate([{**findings[0], "severity": severity}], policy, today)
    reject(lambda: verdict.evaluate(findings, policy, date(2026, 11, 1)))
    reject(lambda: verdict.evaluate(findings, {**policy, "baseline": []}, today))
    invalid = deepcopy(report)
    invalid["matches"][0]["artifact"]["id"] = "unknown"
    reject(lambda: normalizer.normalize(invalid, result, {"version": "fixture"}))
    missing = deepcopy(drvs)
    del missing["patched.drv"]
    reject(lambda: inventory.enrich(deepcopy(system), supply, {}, missing))
print("Security identity, inventory, drift, expiry and severity fixtures passed")
