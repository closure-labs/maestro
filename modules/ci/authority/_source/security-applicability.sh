#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ $# == 3 || $# == 4 ]] || {
  echo 'Usage: maestro-ci-security-applicability FINDINGS.json INVENTORY.cdx.json REPORT.json [report|enforce]' >&2
  exit 2
}
: "${MAESTRO_SECURITY_APPLICABILITY_RULES:?}"
exec xo-nixpkg-security-applicability \
  --findings "$1" --inventory "$2" \
  --rules "$MAESTRO_SECURITY_APPLICABILITY_RULES" --output "$3" \
  --mode "${4:-${SECURITY_APPLICABILITY_MODE:-report}}"
