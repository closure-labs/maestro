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
preflight_enabled=${MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED:-false}
case $preflight_enabled in true|false) ;; *) exit 2 ;; esac
preflight_source=${PUBLICATION_PREFLIGHT_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/publication_preflight.py}
preflight_directory=
preflight_digest=
metadata=
destination_state=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/publication-cache.XXXXXX")
cleanup() {
  rm -f -- "$destination_state" ${metadata:+"$metadata"}
  [[ -z $preflight_directory ]] || rm -rf -- "$preflight_directory"
}
trap cleanup EXIT
publication_admission() {
  if [[ $preflight_enabled == true ]]; then
    python3 "$preflight_source" unchanged --directory "$preflight_directory" --snapshot-digest "$preflight_digest"
  fi
  maestro-ci-decision-publication
  if [[ $preflight_enabled == true ]]; then
    python3 "$preflight_source" fresh --directory "$preflight_directory" --snapshot-digest "$preflight_digest"
  fi
}
inspection_product=$DECISION_PRODUCT
public_environment=()
if [[ $preflight_enabled == true ]]; then
  preflight_directory=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/publication-inputs.XXXXXX")
  preflight_digest=$(python3 "$preflight_source" freeze --directory "$preflight_directory" \
    --product "$DECISION_PRODUCT" --scans "$DECISION_SCANS" \
    --policy "${MAESTRO_SYSTEM_ROOT:-$PWD}/nix/automation/decision-policy.json")
  inspection_product=$preflight_directory/product.json
  # Every subsequent native boundary authenticates these same frozen bytes;
  # concurrent edits to the caller's original files cannot change the product
  # seen by a gate between the before/after identity checks.
  export DECISION_PRODUCT=$preflight_directory/product.json
  export DECISION_SCANS=$preflight_directory/scans.json
  # Public observations inherit only transport/certificate settings and public
  # diagnostic scope. A private empty HOME excludes per-user curl credentials.
  public_environment=(env -i "PATH=$PATH" "HOME=$preflight_directory" "LANG=C.UTF-8"
    "PYTHONDONTWRITEBYTECODE=1"
    "MAESTRO_CI_DIAGNOSTICS=${MAESTRO_CI_DIAGNOSTICS:-false}" "RUNNER_TEMP=${RUNNER_TEMP:-${TMPDIR:-/tmp}}")
  for setting in SSL_CERT_FILE NIX_SSL_CERT_FILE CI_OPERATION_DEADLINE MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED PUBLICATION_CURL_WORKER_SOURCE; do
    [[ -z ${!setting:-} ]] || public_environment+=("$setting=${!setting}")
  done
fi
# No evaluation or builders run in this credentialed publisher. The producer
# already realized, inventoried and attested every exact root.
if [[ $preflight_enabled == false ]]; then
  publication_admission
fi
# Inspect public identities before importing or transferring any closure.
cache_readback=("${public_environment[@]}" python3 "${PUBLICATION_DESTINATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/destinations.py}"
  cache --product "$inspection_product" --cache-url "https://maestro.cachix.org"
  --upstream-cache-url "https://cache.nixos.org" --upstream-cache-url "https://xen-orchestra-ce.cachix.org")
if [[ ${PUBLICATION_REQUIRE_VERIFIED:-false} == true ]]; then
  # A manual trial cannot enter the restore/write route, even if a destination
  # disappears after the controller's earlier verified public inspection.
  cache_readback+=(--require-verified)
fi
inspect_cache() {
  if [[ ${MAESTRO_CI_DIAGNOSTICS:-false} == true ]]; then
    "${cache_readback[@]}" --output "$destination_state" "$@"
  else
    "${cache_readback[@]}" --output "$destination_state" "$@" >/dev/null
  fi
}
if [[ $preflight_enabled == true ]]; then
  inspect_cache
else
  inspect_cache ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"}
fi
if [[ $(jq -er .status "$destination_state") == verified ]]; then
  if [[ $preflight_enabled == true ]]; then
    observation_digest=$(sha256sum "$destination_state" | cut -d' ' -f1)
  fi
  publication_admission
  if [[ $preflight_enabled == true && -n ${PUBLICATION_CACHE_RECEIPT:-} ]]; then
    python3 "$preflight_source" complete --directory "$preflight_directory" \
      --observation "$destination_state" --receipt "$PUBLICATION_CACHE_RECEIPT" \
      --snapshot-digest "$preflight_digest" --observation-digest "$observation_digest"
  fi
  echo 'Public cache verified; no closure import or upload required.'
  exit 0
fi
if [[ $preflight_enabled == true ]]; then
  # A partial destination retains the full pre-import gate and every original
  # handoff, pre-write and journal gate. No authorization result is cached.
  publication_admission
fi
metadata=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-publish-nars.XXXXXX")
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
inspect_cache
if [[ $(jq -er .status "$destination_state") == verified ]]; then
  publication_admission
  "${cache_readback[@]}" --require-verified ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"}
  exit 0
fi
# Recheck live authority after store verification, immediately before writing.
publication_admission
maestro-ci-decision-handoff
publication_admission
export CACHIX_AUTH_TOKEN="$CACHIX_MAESTRO_AUTH_TOKEN"
jq -er '.missing[]' "$destination_state" | cachix push maestro
# Fresh bounded HTTP readback bypasses runner narinfo caches. Stock outputs
# may live only upstream; a conflicting/unavailable primary object still blocks.
# Persist the existing receipt format only after every exact hash is verified.
"${cache_readback[@]}" --require-verified ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"}
