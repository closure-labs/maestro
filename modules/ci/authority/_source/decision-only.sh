#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
operation=${DECISION_ONLY_OPERATION:-inspect}
if [[ $operation == verify ]]; then
  registry_config=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-readonly-registry.XXXXXX")
  trap 'rm -rf -- "$registry_config"' EXIT
  export DOCKER_CONFIG=$registry_config
fi
python3 "$MAESTRO_DECISIONS_SOURCE/decision_only.py" --config "$repo_root/modules/ci/authority/_source/decision-policy.json" \
  --root "${CI_CANDIDATE_ROOT:-$repo_root}" --output "${DECISION_ONLY_OUTPUT:-retained-candidate.json}" "$operation"
