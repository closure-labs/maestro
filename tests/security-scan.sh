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
python3 - "$temporary/inventory" <<'PYTHON'
import hashlib,json,sys,pathlib
context = {"fixture":"runtime"}
context_digest = hashlib.sha256(json.dumps(context,sort_keys=True,separators=(",",":")).encode()).hexdigest()
sbom={"bomFormat":"CycloneDX","properties":[{"name":"maestro:inventoryVersion","value":"2"},{"name":"maestro:runtimeContext","value":json.dumps(context)},{"name":"maestro:runtimeContextDigest","value":context_digest}],"components":[{"type":"library","name":"fixture","version":"1","bom-ref":"fixture","purl":"pkg:nix/fixture@1"}],"dependencies":[]}
for name in ["maestro-system", "xen-orchestra-supply"]:pathlib.Path(sys.argv[1],name+".cdx.json").write_text(json.dumps(sbom))
PYTHON
cat >"$temporary/bin/grype" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == version ]]; then printf '{"version":"fixture"}\n'; exit 0; fi
[[ ${FAKE_GRYPE_FAILURE:-false} == false ]] || exit 2
if [[ $1 == *scanner-check.cdx.json ]]; then
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
sed -i "1c#!${BASH}" "$temporary/bin/grype" "$temporary/bin/cargo"
chmod +x "$temporary/bin/grype" "$temporary/bin/cargo"
"$MAESTRO_CI_SECURITY_SCAN"
jq -e 'length == 2 and any(.[]; .advisory == "RUSTSEC-fixture" and .severity == "critical")' "$temporary/report/findings.json" >/dev/null
for failure in FAKE_GRYPE_FAILURE FAKE_AUDIT_FAILURE; do
  if env "$failure=true" "$MAESTRO_CI_SECURITY_SCAN" >/dev/null 2>&1; then
    echo "Scanner returned success after $failure" >&2; exit 1
  fi
done
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
