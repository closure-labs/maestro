#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
export MAESTRO_REQUIRE_UPSTREAM_HANDOFF=true
arguments=()
[[ ${PUBLICATION_PUBLISH:-false} == true ]] && arguments+=(--publish)
exec python3 "$MAESTRO_PUBLICATION_ASSETS_SOURCE" \
  --config "$repo_root/nix/automation/decision-policy.json" \
  --scans "${DECISION_SCANS:?}" --product "${DECISION_PRODUCT:?}" \
  --directory "${DECISION_DIRECTORY:-candidate-evidence}" --tag "${RELEASE_TAG:?}" \
  --revision "${DECISION_SOURCE_SHA:?}" "${arguments[@]}"
