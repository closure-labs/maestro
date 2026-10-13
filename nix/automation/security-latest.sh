#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
temporary=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-security.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
maestro-ci-download-installer "$temporary/inventory"
SECURITY_INVENTORY="$temporary/inventory" maestro-ci-security-scan
