#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
exec python3 "$MAESTRO_NATIVE_PUBLIC_PROBE_SOURCE" "$@"
