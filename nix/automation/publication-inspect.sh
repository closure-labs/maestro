#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${DECISION_PRODUCT:?}" "${PUBLICATION_DESTINATION:?}"
arguments=("$PUBLICATION_DESTINATION" --product "$DECISION_PRODUCT")
if [[ $PUBLICATION_DESTINATION == cache ]]; then
  arguments+=(--cache-url https://maestro.cachix.org
    --upstream-cache-url https://cache.nixos.org --upstream-cache-url https://xen-orchestra-ce.cachix.org)
else
  if [[ ${PUBLICATION_PURPOSE:-rolling} == release ]]; then
    version=${RELEASE_TAG#v}
  else
    revision=$(jq -er .revision "$DECISION_PRODUCT")
    count=$(git rev-list --count "$revision")
    version="0.2.$count+rev-$revision"
  fi
  arguments+=(--version "$version")
fi
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
