#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$MAESTRO_DECISIONS_SOURCE/readiness.py" --config "$repo_root/nix/automation/decision-policy.json"
