#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ $# == 2 ]]
python3 "$MAESTRO_SECURITY_INVENTORY_SOURCE" "$1" "$2" "$MAESTRO_SECURITY_CONTEXT"
