#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_CI_VALIDATE_STATE:?}" "${MAESTRO_CI_TRUSTED_RUN:?}" "${MAESTRO_CI_VERIFY_INVENTORY:?}"
: "${MAESTRO_CI_DOWNLOAD_INSTALLER:?}" "${MAESTRO_CI_SECURITY_VERDICT:?}"
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/inventory/result-installer/iso"
export MAESTRO_CI_PATH_PREFIX="$temporary/bin"
export GITHUB_REPOSITORY=example/maestro
export FAKE_SECURITY_FIXTURE="$temporary"
sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
inventory=$temporary/inventory
printf 'ISO\n' >"$inventory/result-installer/iso/maestro-installer.iso"
for file in maestro-system xen-orchestra-supply; do
  printf '{"spdxVersion":"SPDX-2.3"}\n' >"$inventory/$file.spdx.json"
  printf '{"bomFormat":"CycloneDX","components":[]}\n' >"$inventory/$file.cdx.json"
done
printf '{"schemaVersion":1}\n' >"$inventory/xen-orchestra-supply.assertion.json"
jq -n --arg sha "$sha" '{schema_version:5,mode:"qualify-media",media_input:("a"*64),evidence_input:("b"*64),source_commit:$sha,artifact_source_commit:$sha,media_source_commit:$sha,producer_event:"push",artifact_run_id:7,media_run_id:7,evidence_run_id:7}' >"$inventory/maestro-qualification-state.json"
(
  cd "$inventory"
  for file in result-installer/iso/maestro-installer.iso maestro-system.spdx.json maestro-system.cdx.json xen-orchestra-supply.assertion.json xen-orchestra-supply.spdx.json xen-orchestra-supply.cdx.json; do
    sha256sum "$file" >"${file##*/}.sha256"
  done
)
cp "$inventory/maestro-system.spdx.json" "$temporary/predicate.json"
(cd "$inventory" && sha256sum result-installer/iso/maestro-installer.iso ./*.json) >"$temporary/signed-digests"
cat >"$temporary/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
fixture=${FAKE_SECURITY_FIXTURE:?}
if [[ $1 == api ]]; then
  case $2 in
    */actions/runs/*) cat "$fixture/run.json" ;;
    */branches/main) cat "$fixture/branch.json" ;;
    */compare/*) cat "$fixture/comparison.json" ;;
    *) exit 1 ;;
  esac
elif [[ "$1 $2" == 'attestation verify' ]]; then
  [[ $* == *'--source-ref refs/heads/main'* && $* == *'--deny-self-hosted-runners'* ]]
  [[ $* == *'--signer-workflow example/maestro/.github/workflows/ci.yml'* ]]
  actual=$(sha256sum "$3")
  grep -Fq "${actual%% *} " "$fixture/signed-digests"
  if [[ $* == *'--format json'* ]]; then
    jq -n --slurpfile predicate "$fixture/predicate.json" '[{verificationResult:{statement:{predicate:$predicate[0]}}}]'
  fi
elif [[ "$1 $2" == 'run list' ]]; then
  printf '7\n'
elif [[ "$1 $2" == 'run download' ]]; then
  [[ $3 == 7 ]]
  name='' destination=''
  while [[ $# -gt 0 ]]; do
    case $1 in --name) name=$2; shift 2 ;; --dir) destination=$2; shift 2 ;; *) shift ;; esac
  done
  if [[ $name == maestro-qualification-state ]]; then
    cp "$fixture/inventory/maestro-qualification-state.json" "$destination/"
  else
    cp -R "$fixture/inventory/." "$destination/"
  fi
else exit 1; fi
EOF
sed -i "1c#!${BASH}" "$temporary/bin/gh"
chmod +x "$temporary/bin/gh"
reset_metadata() {
  jq -n --arg sha "$sha" '{id:7,status:"completed",conclusion:"success",head_repository:{full_name:"example/maestro"},head_branch:"main",head_sha:$sha,path:".github/workflows/ci.yml",event:"push"}' >"$temporary/run.json"
  jq -n --arg sha "$sha" '{protected:true,commit:{sha:$sha}}' >"$temporary/branch.json"
  jq -n --arg sha "$sha" '{merge_base_commit:{sha:$sha}}' >"$temporary/comparison.json"
}
reject() {
  if "$@" >/dev/null 2>&1; then echo "Accepted invalid security input: $*" >&2; exit 1; fi
}
reset_metadata
"$MAESTRO_CI_VALIDATE_STATE" "$inventory/maestro-qualification-state.json"
"$MAESTRO_CI_TRUSTED_RUN" 7 "$sha" >/dev/null
"$MAESTRO_CI_VERIFY_INVENTORY" "$inventory" "$sha"
"$MAESTRO_CI_DOWNLOAD_INSTALLER" "$temporary/download"
[[ $(jq -r .source_commit "$temporary/download/selected-state.json") == "$sha" ]]
for alteration in '.schema_version=4' '.artifact_run_id=0' '.media_input="invalid"' '.source_commit="main"' '.extra=true'; do
  jq "$alteration" "$inventory/maestro-qualification-state.json" >"$temporary/invalid-state.json"
  reject "$MAESTRO_CI_VALIDATE_STATE" "$temporary/invalid-state.json"
done
for alteration in '.conclusion="failure"' '.status="in_progress"' '.event="pull_request"' '.event="merge_group"' '.head_branch="feature"' '.head_repository.full_name="attacker/fork"' '.path=".github/workflows/other.yml"' '.head_sha=("b"*40)'; do
  reset_metadata
  jq "$alteration" "$temporary/run.json" >"$temporary/invalid-run.json"
  mv "$temporary/invalid-run.json" "$temporary/run.json"
  reject "$MAESTRO_CI_TRUSTED_RUN" 7 "$sha"
done
reset_metadata
printf '{"protected":false}\n' >"$temporary/branch.json"
reject "$MAESTRO_CI_TRUSTED_RUN" 7 "$sha"
reset_metadata
printf '{"merge_base_commit":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}\n' >"$temporary/comparison.json"
reject "$MAESTRO_CI_TRUSTED_RUN" 7 "$sha"
reset_metadata
cp "$inventory/maestro-installer.iso.sha256" "$temporary/checksum"
printf '%064d  /etc/passwd\n' 0 >"$inventory/maestro-installer.iso.sha256"
reject "$MAESTRO_CI_VERIFY_INVENTORY" "$inventory" "$sha"
cp "$temporary/checksum" "$inventory/maestro-installer.iso.sha256"
printf 'tampered\n' >>"$inventory/result-installer/iso/maestro-installer.iso"
(cd "$inventory" && sha256sum result-installer/iso/maestro-installer.iso >maestro-installer.iso.sha256)
reject "$MAESTRO_CI_VERIFY_INVENTORY" "$inventory" "$sha"
printf 'ISO\n' >"$inventory/result-installer/iso/maestro-installer.iso"
cp "$temporary/checksum" "$inventory/maestro-installer.iso.sha256"
printf '{"spdxVersion":"SPDX-2.3","unexpected":true}\n' >"$temporary/predicate.json"
reject "$MAESTRO_CI_VERIFY_INVENTORY" "$inventory" "$sha"

# Report-only findings do not block; scanner failures are handled by the scan
# command. Enforcement compares reviewed baselines and expiring exceptions.
printf '[{"advisory":"CVE-fixture","component":"example","version":"1","severity":"high","identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]\n' >"$temporary/findings.json"
cp "$root/modules/ci/authority/_source/security-policy.json" "$temporary/policy.json"
"$MAESTRO_CI_SECURITY_VERDICT" "$temporary/findings.json" "$temporary/policy.json" >/dev/null
jq '.mode="enforce"' "$temporary/policy.json" >"$temporary/enforce.json"
reject "$MAESTRO_CI_SECURITY_VERDICT" "$temporary/findings.json" "$temporary/enforce.json"
jq --arg created "$(date -u +%F)" --arg expires "$(date -u -d tomorrow +%F)" '.dispositions=[{advisory:"CVE-fixture",component:"example",version:"1",severity:"high",identity:("a"*64),kind:"fixed",owner:"operator",reason:"reviewed",evidence:["https://example.invalid/patch"],created:$created,expires:$expires}]' "$temporary/enforce.json" >"$temporary/baseline.json"
"$MAESTRO_CI_SECURITY_VERDICT" "$temporary/findings.json" "$temporary/baseline.json" >/dev/null
jq '.[0].severity="critical"' "$temporary/findings.json" >"$temporary/escalated.json"
reject "$MAESTRO_CI_SECURITY_VERDICT" "$temporary/escalated.json" "$temporary/baseline.json"
today=$(date -u +%F)
tomorrow=$(date -u -d tomorrow +%F)
jq --arg created "$today" --arg expires "$tomorrow" '.exceptions=[{advisory:"CVE-fixture",component:"example",version:"1",severity:"high",identity:("a"*64),owner:"operator",reason:"temporary",evidence:["https://example.invalid/issue"],created:$created,expires:$expires}]' "$temporary/enforce.json" >"$temporary/exception.json"
"$MAESTRO_CI_SECURITY_VERDICT" "$temporary/findings.json" "$temporary/exception.json" >/dev/null
jq '.exceptions[0].created="2020-01-01" | .exceptions[0].expires="2020-01-02"' "$temporary/exception.json" >"$temporary/expired.json"
reject "$MAESTRO_CI_SECURITY_VERDICT" "$temporary/findings.json" "$temporary/expired.json"
printf 'Security contract fixtures passed.\n'

# Public-key enrollment accepts a valid build key and rejects malformed or
# multi-line keys without altering authorization.
ssh-keygen -q -t ed25519 -N '' -C maestro-packer-bootstrap -f "$temporary/build-key"
cat >"$temporary/bin/id" <<'EOF'
#!/usr/bin/env bash
printf '0\n'
EOF
cat >"$temporary/bin/install" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# The fixture validates real permissions, without requiring root chown.
arguments=()
while [[ $# -gt 0 ]]; do
  case $1 in -o|-g) shift 2 ;; *) arguments+=("$1"); shift ;; esac
done
exec "$FAKE_REAL_INSTALL" "${arguments[@]}"
EOF
sed -i "1c#!${BASH}" "$temporary/bin/id" "$temporary/bin/install"
chmod +x "$temporary/bin/id" "$temporary/bin/install"
export FAKE_REAL_INSTALL
FAKE_REAL_INSTALL=$(command -v install)
bootstrap=$temporary/bootstrap
key_b64=$(base64 -w0 "$temporary/build-key.pub")
PATH="$temporary/bin:$PATH" MAESTRO_BOOTSTRAP_DIR="$bootstrap" \
  bash "$root/modules/features/installer/_source/bootstrap-key.sh" "$key_b64"
[[ $(stat -c %a "$bootstrap/authorized_keys") == 644 ]]
cmp "$temporary/build-key.pub" "$bootstrap/authorized_keys"
reject env PATH="$temporary/bin:$PATH" MAESTRO_BOOTSTRAP_DIR="$bootstrap" \
  bash "$root/modules/features/installer/_source/bootstrap-key.sh" 'invalid!'
reject env PATH="$temporary/bin:$PATH" MAESTRO_BOOTSTRAP_DIR="$bootstrap" \
  bash "$root/modules/features/installer/_source/bootstrap-key.sh" "$(printf 'bad\nkey' | base64 -w0)"
cmp "$temporary/build-key.pub" "$bootstrap/authorized_keys"
