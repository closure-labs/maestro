#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$MAESTRO_DECISIONS_SOURCE/admission.py" --config "$repo_root/modules/ci/authority/_source/decision-policy.json" \
  --scans "${DECISION_SCANS:-security-report/scans.json}" --output "${DECISION_ADMISSION:-security-report/admission.json}"
