#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_SECURITY_POLICY:?}"
inventory=${SECURITY_INVENTORY:-candidate}
output=${SECURITY_OUTPUT:-security-report}
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
mkdir -p "$output"
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-scan.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
# Reports must never imply a clean scan after a database or scanner failure.
export GRYPE_DB_CACHE_DIR="$work/grype-db"
export GRYPE_DB_MAX_ALLOWED_BUILT_AGE=24h
export GRYPE_DB_VALIDATE_AGE=true
grype version -o json >"$output/grype-version.json"
cargo audit --version >"$output/cargo-audit-version.txt"
# Prove that both native and JavaScript identities reach the active database.
# Reuse this invocation's fresh database; never run an extra local download.
cat >"$work/scanner-check.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
  {"type":"library","name":"openssl","version":"1.0.1","bom-ref":"nix:scanner-check","purl":"pkg:nix/openssl@1.0.1"},
  {"type":"library","name":"lodash","version":"4.17.15","bom-ref":"npm:scanner-check","purl":"pkg:npm/lodash@4.17.15"}
]}
JSON
grype "sbom:$work/scanner-check.cdx.json" --add-cpes-if-none -o json >"$output/scanner-check.grype.json"
jq -e 'any(.matches[]; .artifact.name == "openssl") and any(.matches[]; .artifact.name == "lodash")' \
  "$output/scanner-check.grype.json" >/dev/null
# Enriched system evidence contains the complete, bound XO dependency tree.
component=maestro-system
sbom=$inventory/$component.cdx.json
jq -e '.bomFormat == "CycloneDX" and (.components | type == "array")' "$sbom" >/dev/null
grype "sbom:$sbom" --add-cpes-if-none -o json >"$output/$component.grype.json"
jq -e '.matches | type == "array"' "$output/$component.grype.json" >/dev/null
python3 "$MAESTRO_SECURITY_NORMALIZE_SOURCE" "$output/$component.grype.json" "$sbom" \
  "$output/grype-version.json" "$work/$component.findings.json"
audit_status=0
cargo audit --file "$repo_root/pkgs/maestro-menu/Cargo.lock" --db "$work/rustsec" --json \
  >"$output/cargo-audit.json" || audit_status=$?
[[ $audit_status == 0 || $audit_status == 1 ]]
jq -e '.vulnerabilities.list | type == "array"' "$output/cargo-audit.json" >/dev/null
# RustSec CVSS vectors become severity through the declared Python CVSS library.
python3 - "$output/cargo-audit.json" "$work/cargo.findings.json" "$repo_root/pkgs/maestro-menu/Cargo.lock" \
  "$output/cargo-audit-version.txt" "$sbom" "${BASH_SOURCE[0]}" <<'PYTHON'
import hashlib
import json
from pathlib import Path
import sys
from cvss import CVSS3, CVSS4
with open(sys.argv[1], encoding="utf-8") as handle:
    audit = json.load(handle)
findings = []
lock_digest = hashlib.sha256(open(sys.argv[3], "rb").read()).hexdigest()
scanner_version = Path(sys.argv[4]).read_text().strip()
context = {p["name"]: p["value"] for p in json.loads(Path(sys.argv[5]).read_text())["properties"]}["maestro:runtimeContextDigest"]
normalizer_digest = hashlib.sha256(Path(sys.argv[6]).read_bytes()).hexdigest()
for entry in audit["vulnerabilities"]["list"]:
    vector = entry["advisory"].get("cvss")
    severity = "unknown"
    if vector:
        calculator = CVSS4(vector) if vector.startswith("CVSS:4.") else CVSS3(vector)
        severity = calculator.severities()[0].lower()
        if severity == "none":
            severity = "negligible"
    binding = {"lockfile": lock_digest, "scanner": "cargo-audit", "normalizer": "2",
               "scanner_version": scanner_version, "runtime_context": context,
               "normalizer_digest": normalizer_digest,
               "component": entry["package"]["name"], "version": entry["package"]["version"]}
    identity = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()
    findings.append({"advisory": entry["advisory"]["id"], "component": entry["package"]["name"],
                     "version": entry["package"]["version"], "severity": severity, "scanner": "cargo-audit", "identity": identity, "binding": binding})
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(findings, handle)
PYTHON

jq -s 'add | unique_by([.advisory,.identity,.severity])' "$work/"*.findings.json >"$output/findings.json"
sha256sum "$inventory/maestro-system.cdx.json" "$inventory/xen-orchestra-supply.cdx.json" \
  "$repo_root/pkgs/maestro-menu/Cargo.lock" >"$output/inputs.sha256"
maestro-ci-security-verdict "$output/findings.json" "$MAESTRO_SECURITY_POLICY" >"$output/new-high-critical.json"
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  printf 'Security scan: %s findings; policy mode %s. Unscored advisories require triage.\n' \
    "$(jq length "$output/findings.json")" "$(jq -r .mode "$MAESTRO_SECURITY_POLICY")" >>"$GITHUB_STEP_SUMMARY"
fi
