#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${GITHUB_REPOSITORY:?}"
[[ $# -ge 1 && $# -le 2 ]] || { echo 'Usage: maestro-ci-download-installer DIRECTORY [evidence]' >&2; exit 2; }
mode=${2:-full}
case $mode in
  full) artifact_name=maestro-installer ;;
  evidence) artifact_name=maestro-evidence ;;
  *) echo 'Only evidence may be specified as a download mode' >&2; exit 2 ;;
esac
destination=$(realpath -m -- "$1")
[[ ! -e $destination ]] || { echo 'Download destination must not exist' >&2; exit 2; }
github_cli=${GH_BIN:-gh}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/maestro-download.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
run_ids=$("$github_cli" run list --repo "$GITHUB_REPOSITORY" --workflow ci.yml \
  --branch main --status success --limit 20 --json databaseId --jq '.[].databaseId')
while read -r run_id; do
  [[ $run_id =~ ^[1-9][0-9]*$ ]] || continue
  rm -rf -- "$temporary/state" "$temporary/inventory"
  mkdir -p "$temporary/state" "$temporary/inventory"
  if ! "$github_cli" run download "$run_id" --repo "$GITHUB_REPOSITORY" \
      --name maestro-qualification-state --dir "$temporary/state" ||
    ! maestro-ci-verify-state "$temporary/state/maestro-qualification-state.json" "$run_id"; then
    continue
  fi
  pointer=$temporary/state/maestro-qualification-state.json
  artifact_run_id=$(jq -er .artifact_run_id "$pointer")
  artifact_sha=$(jq -er .artifact_source_commit "$pointer")
  if ! "$github_cli" run download "$artifact_run_id" --repo "$GITHUB_REPOSITORY" \
      --name "$artifact_name" --dir "$temporary/inventory" ||
    ! maestro-ci-verify-inventory "$temporary/inventory" "$artifact_sha" "$mode"; then
    continue
  fi
  if ! jq -e --slurpfile pointer "$pointer" '
    .media_input == $pointer[0].media_input and .evidence_input == $pointer[0].evidence_input and
    .artifact_run_id == $pointer[0].artifact_run_id and
    .artifact_source_commit == $pointer[0].artifact_source_commit
  ' "$temporary/inventory/maestro-qualification-state.json" >/dev/null; then
    continue
  fi
  cp "$pointer" "$temporary/inventory/selected-state.json"
  mv "$temporary/inventory" "$destination"
  exit 0
done <<<"$run_ids"
echo 'No successful protected-main installer with valid state, inventory, and attestations was found. Force fresh qualification; local/build sources must be selected explicitly.' >&2
exit 1
