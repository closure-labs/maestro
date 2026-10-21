#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
if [[ ${MAESTRO_HANDOFF_BOUNDED:-false} != true ]]; then
  export MAESTRO_HANDOFF_BOUNDED=true
  exec python3 "$MAESTRO_OPERATIONS_SOURCE" --timeout 900 -- bash "$0" "$@"
fi
export PYTHONDONTWRITEBYTECODE=1
registry_config=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-upstream-registry.XXXXXX")
trap 'rm -rf -- "$registry_config"' EXIT
export DOCKER_CONFIG="$registry_config"
printf '%s' "${REGISTRY_TOKEN:?}" | oras login ghcr.io --username "${GITHUB_ACTOR:?}" --password-stdin
python3 "$MAESTRO_DECISION_OPERATIONS_SOURCE"
