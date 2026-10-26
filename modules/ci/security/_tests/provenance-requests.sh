#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_CI_TRUSTED_RUN:?}" "${MAESTRO_CI_VERIFY_INVENTORY:?}"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/inventory/result-installer/iso"
export GITHUB_REPOSITORY=example/maestro
export MAESTRO_CI_PATH_PREFIX="$temporary/bin" PROVENANCE_FIXTURE="$temporary"
sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
other_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
main_sha=cccccccccccccccccccccccccccccccccccccccc
inventory=$temporary/inventory
cat >"$temporary/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
fixture=${PROVENANCE_FIXTURE:?}
if [[ $1 == api ]]; then
  printf '%s\n' "$2" >>"$fixture/requests"
  case $2 in
    */actions/runs/7) cat "$fixture/run-7.json" ;;
    */actions/runs/8) cat "$fixture/run-8.json" ;;
    */branches/main) cat "$fixture/branch.json" ;;
    */compare/*) jq -n --arg sha "${2##*/compare/}" '{merge_base_commit:{sha:($sha | split("...")[0])}}' ;;
    *) exit 1 ;;
  esac
elif [[ "$1 $2" == 'attestation verify' ]]; then
  [[ $* == *'--source-ref refs/heads/main'* && $* == *'--deny-self-hosted-runners'* ]]
  [[ $* == *'--signer-workflow example/maestro/.github/workflows/ci.yml'* ]]
  [[ $* == *"--source-digest $(jq -r .head_sha "$fixture/run-7.json")"* ]]
  digest=$(sha256sum "$3")
  grep -Fqx "$digest" "$fixture/signed-digests"
  printf '%s\n' "$3" >>"$fixture/attestations"
  if [[ $* == *'--format json'* ]]; then
    jq -n --slurpfile predicate "$fixture/inventory/maestro-system.spdx.json" '[{verificationResult:{statement:{predicate:$predicate[0]}}}]'
  fi
else exit 1; fi
EOF
sed -i "1c#!${BASH}" "$temporary/bin/gh"
chmod +x "$temporary/bin/gh"
for run in 7 8; do
  run_sha=$sha
  [[ $run == 7 ]] || run_sha=$other_sha
  jq -n --arg sha "$run_sha" --argjson run "$run" '{id:$run,status:"completed",conclusion:"success",head_repository:{full_name:"example/maestro"},head_branch:"main",head_sha:$sha,path:".github/workflows/ci.yml",event:"push"}' >"$temporary/run-$run.json"
done
jq -n --arg sha "$main_sha" '{protected:true,commit:{sha:$sha}}' >"$temporary/branch.json"
reset_requests() { : >"$temporary/requests"; }
assert_requests() {
  [[ $(wc -l <"$temporary/requests") == "$1" ]]
  [[ $(grep -c '/branches/main$' "$temporary/requests") == 1 ]]
}
reject() {
  if "$@" >/dev/null 2>&1; then
    echo "Accepted invalid provenance input: $*" >&2
    exit 1
  fi
}
reset_requests
[[ $("$MAESTRO_CI_TRUSTED_RUN" 7 "$sha" | jq -r .id) == 7 ]]
assert_requests 3

jq -n --arg sha "$sha" '[{run_id:7,source_sha:$sha},{run_id:7,source_sha:""},{run_id:7,source_sha:$sha}]' >"$temporary/batch.json"
reset_requests
"$MAESTRO_CI_TRUSTED_RUN" --batch <"$temporary/batch.json" >"$temporary/results.json"
[[ $(jq length "$temporary/results.json") == 3 ]]
assert_requests 3
# Each distinct producer and source ancestry is fetched once; main is shared.
jq --arg sha "$other_sha" '. + [{run_id:8,source_sha:$sha}]' "$temporary/batch.json" >"$temporary/mixed.json"
reset_requests
"$MAESTRO_CI_TRUSTED_RUN" --batch <"$temporary/mixed.json" >/dev/null
assert_requests 5
# A prior unconstrained request must never satisfy a later mismatched SHA.
jq --arg sha "$other_sha" '.[0].source_sha="" | .[1].source_sha=$sha' "$temporary/batch.json" >"$temporary/mismatch.json"
reject "$MAESTRO_CI_TRUSTED_RUN" --batch <"$temporary/mismatch.json"
for invalid in '[]' '[{"run_id":0,"source_sha":""}]' '[{"run_id":7,"source_sha":"main"}]' '[{"run_id":7,"source_sha":"","response":{}}]' '[] []'; do
  reset_requests
  reject "$MAESTRO_CI_TRUSTED_RUN" --batch <<<"$invalid"
  [[ ! -s $temporary/requests ]]
done
# Response reuse ends with the invocation, including the protection snapshot.
printf '{"protected":false,"commit":{"sha":"%s"}}\n' "$main_sha" >"$temporary/branch.json"
reject "$MAESTRO_CI_TRUSTED_RUN" --batch <"$temporary/batch.json"
jq -n --arg sha "$main_sha" '{protected:true,commit:{sha:$sha}}' >"$temporary/branch.json"

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
sha256sum "$inventory/result-installer/iso/maestro-installer.iso" "$inventory/"*.json >"$temporary/signed-digests"
reset_requests
"$MAESTRO_CI_VERIFY_INVENTORY" "$inventory" "$sha"
assert_requests 3
[[ $(wc -l <"$temporary/attestations") == 8 ]]
# State validation remains ahead of API calls and attestations.
cp "$inventory/maestro-qualification-state.json" "$temporary/state.json"
jq '.artifact_run_id=0' "$temporary/state.json" >"$inventory/maestro-qualification-state.json"
reset_requests
reject "$MAESTRO_CI_VERIFY_INVENTORY" "$inventory" "$sha"
[[ ! -s $temporary/requests ]]
cp "$temporary/state.json" "$inventory/maestro-qualification-state.json"
printf 'tampered\n' >>"$inventory/maestro-system.cdx.json"
reject "$MAESTRO_CI_VERIFY_INVENTORY" "$inventory" "$sha"
echo 'Invocation-local provenance request and validation fixtures passed.'
