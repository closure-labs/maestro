#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_secret_inventory.py
PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/security/_tests/gitleaks-workflow.py
