#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
export PYTHONDONTWRITEBYTECODE=1
python3 "$MAESTRO_DECISIONS_SOURCE/publication.py" --config "$repo_root/nix/automation/decision-policy.json" \
  --purpose "${PUBLICATION_PURPOSE:-rolling}" --scans "${DECISION_SCANS:-security-report/scans.json}" \
  --product "${DECISION_PRODUCT:-security-report/product.json}" --output "${DECISION_ADMISSION:-security-report/publication.json}"
if [[ ${DECISION_REQUIRE_HANDOFF:-false} == true ]]; then
  maestro-ci-decision-handoff
fi
