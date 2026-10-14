#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# This explicit local operation must never grant cache writes to hosted CI.
[[ ${GITHUB_ACTIONS:-false} != true ]] || {
  echo 'Validation cache publication is available only outside GitHub Actions.' >&2
  exit 1
}
: "${CACHIX_CACHE_NAME:?CACHIX_CACHE_NAME must be configured at runtime}"
: "${MAESTRO_CI_PLAN_CONTRACT:?}"
[[ $# == 1 ]] || { echo 'Usage: maestro-ci-cache-validation MANIFEST.json' >&2; exit 2; }
[[ $CACHIX_CACHE_NAME =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*$ ]] || {
  echo 'Invalid Cachix cache name.' >&2
  exit 2
}
# Accept the complete declared validation plan, never a successful subset or a
# different plan. Only immutable realized output roots reach the Cachix CLI.
jq -e --slurpfile contract "$MAESTRO_CI_PLAN_CONTRACT" '
  type == "object" and
  (keys | sort) == ["failureCount", "flake", "plan", "results", "schemaVersion", "targetCount"] and
  .schemaVersion == 2 and .plan == "maestro-validation" and
  (.flake | type == "string" and length > 0) and
  .failureCount == 0 and
  (.targetCount | type == "number" and floor == . and . > 0) and
  (.results | type == "array" and length == ($contract[0].validation.targets | length)) and
  .targetCount == (.results | length) and
  ([.results[] | {name,attribute}] | sort_by(.name)) ==
    ([$contract[0].validation.targets[] | {name,attribute}] | sort_by(.name)) and
  all(.results[];
    type == "object" and
    (keys | sort) == ["attribute", "name", "outputs", "status"] and
    .status == "success" and
    (.outputs | type == "array" and length > 0 and
      all(.[]; type == "string" and test("^/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[^/[:space:]]+\\z"))))
' "$1" >/dev/null
mapfile -t outputs < <(jq -r '[.results[].outputs[]] | unique[]' "$1")
[[ ${#outputs[@]} -gt 0 ]]
nix path-info "${outputs[@]}" >/dev/null
# Cachix resolves its token from its runtime environment or native user config.
printf '%s\n' "${outputs[@]}" | cachix push "$CACHIX_CACHE_NAME"
