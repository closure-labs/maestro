#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$MAESTRO_DECISIONS_SOURCE/publication_preflight.py" readiness \
  --product "${DECISION_PRODUCT:?}" --scans "${DECISION_SCANS:?}" \
  --policy "${MAESTRO_SYSTEM_ROOT:-$PWD}/modules/ci/authority/_source/decision-policy.json"
