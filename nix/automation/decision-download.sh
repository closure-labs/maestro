#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
if [[ ${MAESTRO_DOWNLOAD_BOUNDED:-false} != true ]]; then
  export MAESTRO_DOWNLOAD_BOUNDED=true
  exec python3 "$MAESTRO_OPERATIONS_SOURCE" --timeout 900 -- bash "$0" "$@"
fi
export PYTHONDONTWRITEBYTECODE=1
status=0
python3 "$MAESTRO_DECISION_DOWNLOAD_SOURCE" || status=$?
if [[ $status == 3 ]]; then
  registry_config=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-retained-registry.XXXXXX")
  trap 'rm -rf -- "$registry_config"' EXIT
  export DOCKER_CONFIG="$registry_config"
  printf '%s' "${REGISTRY_TOKEN:-${GH_TOKEN:?}}" | oras login ghcr.io --username "${GITHUB_ACTOR:?}" --password-stdin
  arguments=()
  [[ ${CANDIDATE_RELEASE_ONLY:-false} == true ]] && arguments+=(--release-only)
  [[ -n ${CANDIDATE_PROPOSAL_HASH:-} ]] && arguments+=(--proposal-hash "$CANDIDATE_PROPOSAL_HASH" --admitted-release)
  [[ ${CANDIDATE_OPTIONAL:-false} == true ]] && arguments+=(--optional)
  python3 "$MAESTRO_DECISION_RETAINED_SOURCE" \
    --config "${MAESTRO_SYSTEM_ROOT:-$PWD}/nix/automation/decision-policy.json" \
    --directory "${DECISION_DIRECTORY:-candidate-evidence}" "${arguments[@]}"
  exit 0
fi
exit "$status"
