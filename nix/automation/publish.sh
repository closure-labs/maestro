#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

[[ ${GITHUB_EVENT_NAME:-} == push && ${GITHUB_REF:-} == refs/heads/main ]] || {
  echo 'Rolling publication requires a protected-main push.' >&2; exit 1;
}

: "${CACHIX_MAESTRO_AUTH_TOKEN:?CACHIX_MAESTRO_AUTH_TOKEN must be set}"
: "${CACHIX_MAESTRO_PUBKEY:?CACHIX_MAESTRO_PUBKEY must be set}"
[[ $CACHIX_MAESTRO_PUBKEY == 'maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0=' ]] || {
  echo 'Maestro Cachix public key differs from the reviewed repository configuration.' >&2
  exit 2
}
export CACHIX_AUTH_TOKEN="$CACHIX_MAESTRO_AUTH_TOKEN"
repo_root=${MAESTRO_SYSTEM_ROOT:-}
if [[ -z "$repo_root" ]]; then
  repo_root=$(git rev-parse --show-toplevel)
fi
cd "$repo_root"

manifest=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-publish-plan.XXXXXX")
trap 'rm -f -- "$manifest"' EXIT
flake-plan-runner \
  --flake . \
  --plan lib.ciPlans.x86_64-linux.publish \
  --manifest "$manifest"
jq -r '.results[].outputs[]' "$manifest" |
  cachix push maestro
