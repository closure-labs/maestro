#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
exec python3 "$MAESTRO_RELEASE_COMPLETION_SOURCE" --reserve \
  --config "$repo_root/modules/ci/authority/_source/decision-policy.json" \
  --scans "${DECISION_SCANS:?}" --product "${DECISION_PRODUCT:?}" \
  --directory "${DECISION_DIRECTORY:-candidate-evidence}" --tag "${RELEASE_TAG:?}" \
  --revision "${DECISION_SOURCE_SHA:?}"
