#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
case ${GITHUB_EVENT_NAME:-} in workflow_run|workflow_dispatch|schedule) ;; *)
  echo 'Publication requires the trusted completed-candidate controller.' >&2; exit 2 ;;
esac
[[ ${GITHUB_REF:-} == refs/heads/main ]]
: "${DECISION_PRODUCT:?}" "${DECISION_SCANS:?}"
: "${PUBLICATION_PURPOSE:=rolling}"
case $PUBLICATION_PURPOSE in rolling|release) ;; *)
  echo 'Unsupported publication purpose.' >&2; exit 2 ;;
esac
export PUBLICATION_PURPOSE
# No evaluation or builders run in this credentialed publisher. The producer
# already realized, inventoried and attested every exact root.
maestro-ci-decision-publication
# Inspect public identities before importing or transferring any closure.
destination_state=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/publication-cache.XXXXXX")
trap 'rm -f -- "$destination_state"' EXIT
cache_readback=(python3 "${PUBLICATION_DESTINATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/destinations.py}"
  cache --product "$DECISION_PRODUCT" --cache-url "https://maestro.cachix.org"
  --upstream-cache-url "https://cache.nixos.org" --upstream-cache-url "https://xen-orchestra-ce.cachix.org")
"${cache_readback[@]}" ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"} >"$destination_state"
if [[ $(jq -er .status "$destination_state") == verified ]]; then
  maestro-ci-decision-publication
  echo 'Public cache verified; no closure import or upload required.'
  exit 0
fi
metadata=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-publish-nars.XXXXXX")
trap 'rm -f -- "$metadata" "$destination_state"' EXIT
# Even existing local roots must be compared with the authenticated retained
# closure. Remote reference lists select observations, never upload authority.
DISTRIBUTION_CLOSURE_METADATA="$metadata" maestro-ci-distribution-restore
: "${CACHIX_MAESTRO_AUTH_TOKEN:?}" "${CACHIX_MAESTRO_PUBKEY:?}"
[[ $CACHIX_MAESTRO_PUBKEY == 'maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0=' ]]
mapfile -t outputs < <(jq -er '[.products[].storePath, .roots[].storePath] | unique[]' "$DECISION_PRODUCT")
[[ ${#outputs[@]} -gt 0 ]]
# Inspect every retained path, including children of missing public roots, and
# compare any existing public dependency hash before selecting missing uploads.
cache_readback+=(--closure-metadata "$metadata")
"${cache_readback[@]}" >"$destination_state"
if [[ $(jq -er .status "$destination_state") == verified ]]; then
  maestro-ci-decision-publication
  "${cache_readback[@]}" --require-verified ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"}
  exit 0
fi
# Recheck live authority after store verification, immediately before writing.
maestro-ci-decision-publication
maestro-ci-decision-handoff
maestro-ci-decision-publication
export CACHIX_AUTH_TOKEN="$CACHIX_MAESTRO_AUTH_TOKEN"
jq -er '.missing[]' "$destination_state" | cachix push maestro
# Fresh bounded HTTP readback bypasses runner narinfo caches. Stock outputs
# may live only upstream; a conflicting/unavailable primary object still blocks.
# Persist the existing receipt format only after every exact hash is verified.
"${cache_readback[@]}" --require-verified ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"}
