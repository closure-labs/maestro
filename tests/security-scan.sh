#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_CI_SECURITY_SCAN:?}"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/inventory" "$temporary/repo/pkgs/maestro-menu" "$temporary/repo/nix/automation"
export MAESTRO_CI_PATH_PREFIX="$temporary/bin"
export MAESTRO_SYSTEM_ROOT="$temporary/repo"
export SECURITY_INVENTORY="$temporary/inventory"
export SECURITY_OUTPUT="$temporary/report"
printf '{"schema_version":2,"mode":"report","dispositions":[],"exceptions":[]}\n' >"$temporary/repo/nix/automation/security-policy.json"
printf 'lockfile fixture\n' >"$temporary/repo/pkgs/maestro-menu/Cargo.lock"
python3 - "$temporary/inventory" "$(readlink -f "$BASH")" <<'PYTHON'
import hashlib,json,sys,pathlib
context = {"schemaVersion":2,"runtime":{
    "allowedTCPPorts":[],"allowedUDPPorts":[],"managementCIDRs":["0.0.0.0/0","::/0"],
    "ssh":{"PasswordAuthentication":False,"PermitRootLogin":"no"},
    "xoUser":"xo","User":"xo","Group":"xo","CapabilityBoundingSet":["CAP_NET_BIND_SERVICE"],
    "AmbientCapabilities":["CAP_NET_BIND_SERVICE"],"fileRestore":{"enable":False},
    "storage":{"enableNFS":False,"enableCIFS":False,"enableVHD":False,"mountsDir":"/run/xo"},"sudo":[]}}
context_digest = hashlib.sha256(json.dumps(context,sort_keys=True,separators=(",",":")).encode()).hexdigest()
sbom={"bomFormat":"CycloneDX","metadata":{"component":{"bom-ref":"fixture-root","name":"fixture-system"}},"properties":[{"name":"maestro:inventoryVersion","value":"2"},{"name":"maestro:runtimeContext","value":json.dumps(context)},{"name":"maestro:runtimeContextDigest","value":context_digest}],"components":[{"type":"library","name":"fixture","version":"1","bom-ref":"fixture","purl":"pkg:nix/fixture@1"}],"dependencies":[]}
root = str(pathlib.Path(sys.argv[2]).parents[1])
assert root.startswith('/nix/store/')
props = [{"name":"nix:storePath","value":root},{"name":"maestro:outputName","value":"out"}]
sbom['components'][0]['properties'] = props
sbom['components'].append({"type":"application","name":"maestro-menu","version":"1","bom-ref":"menu","purl":"pkg:nix/maestro-menu@1","properties":props})
sbom['properties'].append({"name":"maestro:inventoryRoots","value":json.dumps([{"storePath":root,"narHash":"sha256-" + "A" * 43 + "="}])})
for name in ["maestro-system", "xen-orchestra-supply"]:pathlib.Path(sys.argv[1],name+".cdx.json").write_text(json.dumps(sbom))
PYTHON
cat >"$temporary/bin/grype" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == --config && $(cat "$2") == '{}' ]]
shift 2
[[ $GRYPE_DB_MAX_ALLOWED_BUILT_AGE == 48h && $GRYPE_DB_VALIDATE_AGE == true &&
   $GRYPE_DB_AUTO_UPDATE == true && $GRYPE_DB_REQUIRE_UPDATE_CHECK == true ]]
[[ -z ${GRYPE_DB_UPDATE_URL:-}${GRYPE_IGNORE:-}${GRYPE_CONFIG:-} ]]
if [[ $1 == version ]]; then printf '{"version":"fixture"}\n'; exit 0; fi
if [[ "$1 ${2:-}" == 'db status' ]]; then
  if [[ ${FAKE_GRYPE_DB_STALE:-false} == true || ${FAKE_GRYPE_UPDATE_FAILURE:-false} == true ]]; then
    printf '{"valid":false,"error":"database unavailable or expired"}\n'; exit 2
  fi
  printf '{"valid":%s,"built":"%s","schemaVersion":"6.1.10"}\n' "${FAKE_GRYPE_DB_VALID:-true}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  exit 0
fi
[[ ${FAKE_GRYPE_FAILURE:-false} == false ]] || exit 2
[[ ${FAKE_GRYPE_DB_STALE:-false} == false && ${FAKE_GRYPE_UPDATE_FAILURE:-false} == false ]] || exit 2
if [[ $1 == *scanner-check.cdx.json ]]; then
  if [[ ${FAKE_GRYPE_MISSING_NPM:-false} == true ]]; then
    printf '{"matches":[{"artifact":{"name":"openssl"}}]}\n'; exit 0
  fi
  printf '{"matches":[{"artifact":{"name":"openssl"}},{"artifact":{"name":"lodash"}}]}\n'; exit 0
fi
printf '{"matches":[{"vulnerability":{"id":"CVE-fixture","severity":"High","namespace":"nvd:cpe"},"artifact":{"id":"fixture","name":"fixture","version":"1","purl":"pkg:nix/fixture@1"},"matchDetails":[{"type":"cpe-match"}]}]}\n'
EOF
cat >"$temporary/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${2:-} == --version ]]; then printf '%s\n' "${FAKE_AUDIT_VERSION:-cargo-audit fixture}"; exit 0; fi
if [[ ${FAKE_AUDIT_FAILURE:-false} == true ]]; then printf '{"error":"database unavailable"}\n'; exit 1; fi
printf '{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-fixture","cvss":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},"package":{"name":"crate","version":"1"}}]}}\n'
exit 1
EOF
cat >"$temporary/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == -C && $2 == */rustsec && $3 == rev-parse && $4 == HEAD ]]
printf '%040d\n' 1
EOF
sed -i "1c#!${BASH}" "$temporary/bin/grype" "$temporary/bin/cargo" "$temporary/bin/git"
chmod +x "$temporary/bin/grype" "$temporary/bin/cargo" "$temporary/bin/git"
# Ambient flags and config discovery must not suppress scanning or updates.
env GRYPE_DB_MAX_ALLOWED_BUILT_AGE=999h GRYPE_DB_VALIDATE_AGE=false \
  GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_REQUIRE_UPDATE_CHECK=false \
  GRYPE_DB_UPDATE_URL=https://example.invalid/old-db GRYPE_IGNORE=all \
  GRYPE_CONFIG=/nonexistent/ignore-everything.yaml "$MAESTRO_CI_SECURITY_SCAN"
jq -e '.valid == true and (.built | endswith("Z"))' "$temporary/report/grype-database.json" >/dev/null
jq -e '.status == "complete" and .scannerHealth == "healthy" and .securityContext.execution.User == "xo" and (.observations | length == 2) and all(.observations[]; .locationCoverage == "complete" and (.exposureBindings | length > 0))' "$temporary/report/security-result.json" >/dev/null
jq -e 'length == 2 and any(.[]; .advisory == "RUSTSEC-fixture" and .severity == "critical")' "$temporary/report/findings.json" >/dev/null
jq -e '.mode == "report" and (.results | length == 2) and (.unresolved_critical | length == 1) and (.dispositions | length == 0)' "$temporary/report/critical-applicability.json" >/dev/null
# Reusing that successful output directory must yield current failure metadata,
# with no previous finding verdict available to masquerade as this attempt.
if FAKE_GRYPE_UPDATE_FAILURE=true "$MAESTRO_CI_SECURITY_SCAN" >/dev/null 2>&1; then
  echo 'Scanner reused a successful report after a failed database refresh.' >&2; exit 1
fi
jq -e '.valid == false and .error != null' "$temporary/report/grype-database.json" >/dev/null
[[ ! -e "$temporary/report/findings.json" && ! -e "$temporary/report/critical-applicability.json" && ! -e "$temporary/report/security-result.json" ]]
for failure in FAKE_GRYPE_FAILURE FAKE_AUDIT_FAILURE FAKE_GRYPE_DB_STALE \
  FAKE_GRYPE_UPDATE_FAILURE FAKE_GRYPE_MISSING_NPM; do
  rm -rf -- "$temporary/report"
  if env "$failure=true" "$MAESTRO_CI_SECURITY_SCAN" >/dev/null 2>&1; then
    echo "Scanner returned success after $failure" >&2; exit 1
  fi
  [[ ! -e "$temporary/report/findings.json" ]]
  [[ -s "$temporary/report/grype-database.json" ]]
done
rm -rf -- "$temporary/report"
if FAKE_GRYPE_DB_VALID=false "$MAESTRO_CI_SECURITY_SCAN" >/dev/null 2>&1; then
  echo 'Scanner accepted invalid database status.' >&2; exit 1
fi
[[ ! -e "$temporary/report/findings.json" ]]
jq '.mode="enforce"' "$temporary/repo/nix/automation/security-policy.json" >"$temporary/enforce.json"
mv "$temporary/enforce.json" "$temporary/repo/nix/automation/security-policy.json"
if "$MAESTRO_CI_SECURITY_SCAN" >/dev/null 2>&1; then
  echo 'Enforced scan accepted new high/critical findings.' >&2; exit 1
fi
# Editing decision records must not alter scanner identities. Tool changes
# must reopen even an otherwise identical, reviewed RustSec finding.
cp "$temporary/report/findings.json" "$temporary/original-findings.json"
jq --arg created "$(date -u +%F)" --arg expires "$(date -u -d tomorrow +%F)" '
  {schema_version:2,mode:"enforce",exceptions:[],dispositions:map({advisory,component,version,severity,identity,kind:"fixed",owner:"fixture",reason:"reviewed fixture",evidence:["https://example.invalid/patch"],created:$created,expires:$expires})}
' "$temporary/original-findings.json" >"$temporary/repo/nix/automation/security-policy.json"
"$MAESTRO_CI_SECURITY_SCAN"
cmp "$temporary/original-findings.json" "$temporary/report/findings.json"
if FAKE_AUDIT_VERSION='cargo-audit changed' "$MAESTRO_CI_SECURITY_SCAN" >/dev/null 2>&1; then
  echo 'Scanner drift retained an old RustSec disposition.' >&2; exit 1
fi
printf 'Security scanner fixtures passed.\n'
