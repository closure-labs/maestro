#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${DECISION_PRODUCT:?}" "${PUBLICATION_DESTINATION:?}"
[[ $PUBLICATION_DESTINATION == cache ]] || { printf '%s\n' 'Only cache publication inspection is supported' >&2; exit 1; }
arguments=(cache --product "$DECISION_PRODUCT" --cache-url https://maestro.cachix.org
  --upstream-cache-url https://cache.nixos.org --upstream-cache-url https://xen-orchestra-ce.cachix.org)
[[ ${PUBLICATION_REQUIRE_VERIFIED:-false} == true ]] && arguments+=(--require-verified)
[[ -n ${PUBLICATION_RECEIPT:-} ]] && arguments+=(--receipt "$PUBLICATION_RECEIPT")
status=0
state=$(python3 "$PUBLICATION_DESTINATIONS_SOURCE" "${arguments[@]}") || status=$?
printf '%s\n' "$state"
if (( status != 0 )); then
  exit "$status"
fi
if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  printf 'status=%s\n' "$(jq -er .status <<<"$state")" >>"$GITHUB_OUTPUT"
fi
