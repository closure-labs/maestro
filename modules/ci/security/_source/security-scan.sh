#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_SECURITY_POLICY:?}"
inventory=${SECURITY_INVENTORY:-candidate}
output=${SECURITY_OUTPUT:-security-report}
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
cargo_lock=${SECURITY_CARGO_LOCK:-$repo_root/modules/features/operator/menu/_source/frontend/Cargo.lock}
scan_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$output"
# Reusing an output directory must not leave a previous successful verdict or
# database status behind when the current invocation fails before replacing it.
rm -f -- "$output/grype-database.json" "$output/findings.json" \
  "$output/grype-findings.json" "$output/critical-applicability.json" \
  "$output/effective-policy.json" "$output/new-high-critical.json" "$output/inputs.sha256" \
  "$output/security-result.json"
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-scan.XXXXXX")
printf '{}\n' >"$work/grype.yaml"
# Local configuration must not disable database updates, hide findings, or
# replace the reviewed database source. CI and workstation scans use one policy.
for variable in "${!GRYPE_@}"; do unset "$variable"; done
run_grype() { grype --config "$work/grype.yaml" "$@"; }
cleanup() {
  # Keep database diagnostics even if download, age validation or a probe fails.
  if [[ ! -s "$output/grype-database.json" ]]; then
    run_grype db status -o json >"$output/grype-database.json" || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT
# Reports must never imply a clean scan after a database or scanner failure.
export GRYPE_DB_CACHE_DIR="$work/grype-db"
# Daily builds are published later than their build timestamp. A 24-hour limit
# rejects the newest published DB during that daily gap; allow two daily cycles.
export GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h
export GRYPE_DB_VALIDATE_AGE=true
export GRYPE_DB_AUTO_UPDATE=true
export GRYPE_DB_REQUIRE_UPDATE_CHECK=true
run_grype version -o json >"$output/grype-version.json"
cargo-audit audit --version >"$output/cargo-audit-version.txt"
# Prove that both native and JavaScript identities reach the active database.
# Reuse this invocation's fresh database; never run an extra local download.
cat >"$work/scanner-check.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
  {"type":"library","name":"openssl","version":"1.0.1","bom-ref":"nix:scanner-check","purl":"pkg:nix/openssl@1.0.1"},
  {"type":"library","name":"lodash","version":"4.17.15","bom-ref":"npm:scanner-check","purl":"pkg:npm/lodash@4.17.15"}
]}
JSON
run_grype "sbom:$work/scanner-check.cdx.json" --add-cpes-if-none -o json >"$output/scanner-check.grype.json"
jq -e 'any(.matches[]; .artifact.name == "openssl") and any(.matches[]; .artifact.name == "lodash")' \
  "$output/scanner-check.grype.json" >/dev/null
# Enriched system evidence contains the complete, bound XO dependency tree.
component=maestro-system
sbom=$inventory/$component.cdx.json
jq -e '.bomFormat == "CycloneDX" and (.components | type == "array")' "$sbom" >/dev/null
run_grype "sbom:$sbom" --add-cpes-if-none -o json >"$output/$component.grype.json"
jq -e '.matches | type == "array"' "$output/$component.grype.json" >/dev/null
run_grype db status -o json >"$output/grype-database.json"
jq -e '.valid == true' "$output/grype-database.json" >/dev/null
python3 "$MAESTRO_SECURITY_NORMALIZE_SOURCE" "$output/$component.grype.json" "$sbom" \
  "$output/grype-version.json" "$work/$component.findings.json"
audit_status=0
cargo-audit audit --file "$cargo_lock" --db "$work/rustsec" --json \
  >"$output/cargo-audit.json" || audit_status=$?
[[ $audit_status == 0 || $audit_status == 1 ]]
jq -e '.vulnerabilities.list | type == "array"' "$output/cargo-audit.json" >/dev/null
# A fresh temporary database is fetched by this exact cargo-audit invocation.
# Record the native revision rather than assigning freshness to reused bytes.
rustsec_revision=$(git -C "$work/rustsec" rev-parse HEAD)
[[ $rustsec_revision =~ ^[a-f0-9]{40}$ ]]
jq -n --arg revision "$rustsec_revision" --arg fetchedAt "$scan_started" \
  '{source:"https://github.com/RustSec/advisory-db.git",revision:$revision,fetchedAt:$fetchedAt}' \
  >"$output/rustsec-database.json"
# RustSec CVSS vectors become severity through the declared Python CVSS library.
python3 - "$output/cargo-audit.json" "$work/cargo.findings.json" "$cargo_lock" \
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
               "advisory_digest": hashlib.sha256(json.dumps(entry["advisory"], sort_keys=True).encode()).hexdigest(),
               "component": entry["package"]["name"], "version": entry["package"]["version"]}
    identity = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()
    findings.append({"advisory": entry["advisory"]["id"], "component": entry["package"]["name"],
                     "version": entry["package"]["version"], "severity": severity, "scanner": "cargo-audit", "identity": identity, "binding": binding})
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(findings, handle)
PYTHON

jq -s 'add | unique_by([.advisory,.identity,.severity])' "$work/"*.findings.json >"$output/findings.json"
jq '[.[] | select(.scanner == "grype")]' "$output/findings.json" >"$output/grype-findings.json"
# Revalidate reviewed source fixes and attack-surface constraints on this exact
# inventory. Unknown findings remain visible; applicability does not lower a
# scanner's severity or turn an incomplete call graph into an exclusion.
maestro-ci-security-applicability "$output/grype-findings.json" "$sbom" \
  "$output/critical-applicability.json"
# RustSec findings bind the lockfile rather than a CycloneDX component. Keep
# them unresolved in the machine report and subject to the existing policy.
jq --slurpfile findings "$output/findings.json" '
  .results += [$findings[0][] | select(.scanner != "grype") |
    {finding: ., classification: "unresolved", rule_id: null,
     reason: "This lockfile finding requires remediation or its existing exact policy decision."}] |
  .unresolved_critical += [$findings[0][] |
    select(.scanner != "grype" and .severity == "critical")]
' "$output/critical-applicability.json" >"$work/applicability.json"
mv "$work/applicability.json" "$output/critical-applicability.json"
# Human decisions retain precedence. Fresh machine decisions use the same
# exact finding identities and expiry contract as the existing verdict.
jq --slurpfile applicability "$output/critical-applicability.json" '
  def key: [.advisory, .component, .version, .severity, .identity];
  ([.dispositions[], .exceptions[]] | map(key)) as $reviewed |
  .dispositions += [$applicability[0].dispositions[] |
    select(key as $candidate | $reviewed | index($candidate) | not)]
' "$MAESTRO_SECURITY_POLICY" >"$output/effective-policy.json"
sha256sum "$inventory/maestro-system.cdx.json" "$inventory/xen-orchestra-supply.cdx.json" \
  "$cargo_lock" >"$output/inputs.sha256"
# This is native technical evidence, independent of the historical report-mode
# policy. Publication must separately require authenticated human admission.
python3 "$MAESTRO_SECURITY_NORMALIZE_SOURCE" --result "$output" "$sbom" "$scan_started"
maestro-ci-security-verdict "$output/findings.json" "$output/effective-policy.json" >"$output/new-high-critical.json"
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  printf 'Security scan: %s findings; policy mode %s. Unscored advisories require triage.\n' \
    "$(jq length "$output/findings.json")" "$(jq -r .mode "$MAESTRO_SECURITY_POLICY")" >>"$GITHUB_STEP_SUMMARY"
  jq -r '
    "Critical applicability: \([.results[] | select(.finding.severity == "critical" and .classification == "fixed")] | length) verified fixed; " +
    "\([.results[] | select(.finding.severity == "critical" and .classification == "not_affected")] | length) verified not affected; " +
    "\(.unresolved_critical | length) unresolved. Raw findings are retained."
  ' "$output/critical-applicability.json" >>"$GITHUB_STEP_SUMMARY"
fi
