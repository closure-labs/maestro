#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$MAESTRO_DECISIONS_SOURCE/recovery.py" --config "$repo_root/modules/ci/authority/_source/decision-policy.json" \
  --journal "${DECISION_JOURNAL:-publication-journal.json}" --product "${DECISION_PRODUCT:-security-report/product.json}" \
  --scans "${DECISION_SCANS:-security-report/scans.json}"
