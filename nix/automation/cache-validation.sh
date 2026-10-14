#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# This explicit local operation must never grant cache writes to hosted CI.
[[ ${GITHUB_ACTIONS:-false} != true ]] || {
  echo 'Validation cache publication is available only outside GitHub Actions.' >&2
  exit 1
}
: "${CACHIX_MAESTRO_AUTH_TOKEN:?CACHIX_MAESTRO_AUTH_TOKEN must be configured at runtime}"
: "${CACHIX_MAESTRO_PUBKEY:?CACHIX_MAESTRO_PUBKEY must be configured at runtime}"
: "${MAESTRO_CI_PLAN_CONTRACT:?}"
[[ $# == 1 ]] || { echo 'Usage: maestro-ci-cache-validation MANIFEST.json' >&2; exit 2; }
[[ $CACHIX_MAESTRO_PUBKEY == 'maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0=' ]] || {
  echo 'Maestro Cachix public key differs from the reviewed repository configuration.' >&2
  exit 2
}
# Accept the complete declared validation plan, never a successful subset or a
# different plan. Only immutable realized output roots reach the Cachix CLI.
manifest=$(jq -ces --slurpfile contract "$MAESTRO_CI_PLAN_CONTRACT" '
  select(length == 1) | .[0] |
  select(type == "object" and
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
      all(.[]; type == "string" and test("^/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[^/[:space:]]+\\z")))))
' "$1")
mapfile -t outputs < <(jq -r '[.results[].outputs[]] | unique[]' <<<"$manifest")
[[ ${#outputs[@]} -gt 0 ]]
nix path-info "${outputs[@]}" >/dev/null
# Override any ambient Cachix token: only the Maestro credential may publish.
export CACHIX_AUTH_TOKEN="$CACHIX_MAESTRO_AUTH_TOKEN"
printf '%s\n' "${outputs[@]}" | cachix push maestro
