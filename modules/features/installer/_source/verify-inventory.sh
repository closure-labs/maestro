#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
[[ $# -ge 2 && $# -le 3 && $2 =~ ^[0-9a-f]{40}$ ]] || {
  echo 'Usage: maestro-ci-verify-inventory DIRECTORY ARTIFACT_SOURCE_SHA [evidence]' >&2; exit 2;
}
inventory=$(realpath -- "$1")
source_sha=$2
github_cli=${GH_BIN:-gh}
state=$inventory/maestro-qualification-state.json
[[ -f $state && ! -L $state ]]
maestro-ci-validate-state "$state"
[[ $(jq -er .artifact_source_commit "$state") == "$source_sha" ]]
jq -c '[
  {run_id:.artifact_run_id,source_sha:.artifact_source_commit},
  {run_id:.media_run_id,source_sha:.media_source_commit},
  {run_id:.evidence_run_id,source_sha:""}
]' "$state" | maestro-ci-trusted-run --batch >/dev/null

files=(
  maestro-system.spdx.json maestro-system.cdx.json
  xen-orchestra-supply.assertion.json
  xen-orchestra-supply.spdx.json xen-orchestra-supply.cdx.json
)
case ${3:-full} in
  full) files=(result-installer/iso/maestro-installer.iso "${files[@]}") ;;
  evidence) ;;
  *) exit 2 ;;
esac
signer_workflow="$GITHUB_REPOSITORY/.github/workflows/ci.yml"
verify_args=(--repo "$GITHUB_REPOSITORY" --signer-workflow "$signer_workflow"
  --source-ref refs/heads/main --source-digest "$source_sha" --signer-digest "$source_sha"
  --deny-self-hosted-runners)
for file in "${files[@]}"; do
  checksum=${file##*/}.sha256
  [[ -f $inventory/$file && ! -L $inventory/$file && ! -L $inventory/$checksum ]]
  [[ $(realpath -- "$inventory/$file") == "$inventory/$file" ]]
  # Never pass an artifact-controlled filename to sha256sum --check.
  expected=$(<"$inventory/$checksum")
  digest=${expected%% *}
  [[ $digest =~ ^[0-9a-f]{64}$ && $expected == "$digest  $file" ]]
  actual=$(sha256sum -- "$inventory/$file")
  [[ ${actual%% *} == "$digest" ]]
  "$github_cli" attestation verify "$inventory/$file" "${verify_args[@]}" >/dev/null
done
"$github_cli" attestation verify "$state" "${verify_args[@]}" >/dev/null
[[ ${3:-full} != evidence ]] || exit 0
spdx_version=$(jq -er .spdxVersion "$inventory/maestro-system.spdx.json")
[[ $spdx_version == SPDX-2.3 ]]
verified=$("$github_cli" attestation verify "$inventory/result-installer/iso/maestro-installer.iso" \
  "${verify_args[@]}" --predicate-type https://spdx.dev/Document/v2.3 --format json)
jq -e --slurpfile sbom "$inventory/maestro-system.spdx.json" \
  'any(.[]; .verificationResult.statement.predicate == $sbom[0])' <<<"$verified" >/dev/null
