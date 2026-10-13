#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: maestro-ci-security-verdict FINDINGS.json POLICY.json' >&2; exit 2; }
exec python3 "$MAESTRO_SECURITY_VERDICT_SOURCE" "$1" "$2"
