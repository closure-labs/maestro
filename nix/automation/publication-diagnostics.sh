#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Finalize evidence only. This command never repeats admission or publication.
exec python3 "$MAESTRO_DECISIONS_SOURCE/diagnostics.py"
