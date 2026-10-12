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
printf '{"schema_version":1,"mode":"report","baseline":[],"exceptions":[]}\n' >"$temporary/repo/nix/automation/security-policy.json"
printf 'lockfile fixture\n' >"$temporary/repo/pkgs/maestro-menu/Cargo.lock"
for component in maestro-system xen-orchestra-supply; do
  printf '{"bomFormat":"CycloneDX","components":[]}\n' >"$temporary/inventory/$component.cdx.json"
done
cat >"$temporary/bin/grype" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == version ]]; then printf '{"version":"fixture"}\n'; exit 0; fi
[[ ${FAKE_GRYPE_FAILURE:-false} == false ]] || exit 2
printf '{"matches":[{"vulnerability":{"id":"CVE-fixture","severity":"High"},"artifact":{"name":"fixture","version":"1"}}]}\n'
EOF
cat >"$temporary/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${2:-} == --version ]]; then printf 'cargo-audit fixture\n'; exit 0; fi
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
printf 'Security scanner fixtures passed.\n'
