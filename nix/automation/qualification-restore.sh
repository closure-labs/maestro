#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$MAESTRO_QUALIFICATION_RESTORE_SOURCE"
