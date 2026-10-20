#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
export PYTHONDONTWRITEBYTECODE=1
registry_config=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-authority-registry.XXXXXX")
trap 'rm -rf -- "$registry_config"' EXIT
export DOCKER_CONFIG="$registry_config"
printf '%s' "${REGISTRY_TOKEN:?}" | oras login ghcr.io --username "${GITHUB_ACTOR:?}" --password-stdin
python3 "$MAESTRO_DECISIONS_SOURCE/check.py" --config "$repo_root/nix/automation/decision-policy.json" \
  --collector-run "${COLLECTOR_RUN:?}"
