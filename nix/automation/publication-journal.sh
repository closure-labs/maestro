#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
exec python3 "$MAESTRO_PUBLICATION_JOURNAL_SOURCE" \
  --config "$repo_root/nix/automation/decision-policy.json" \
  --scans "${DECISION_SCANS:?}" --product "${DECISION_PRODUCT:?}" \
  --key "${PUBLICATION_KEY:?}" --step "${PUBLICATION_STEP:?}" \
  --state "${PUBLICATION_STATE:?}" --purpose "${PUBLICATION_PURPOSE:-release}"
