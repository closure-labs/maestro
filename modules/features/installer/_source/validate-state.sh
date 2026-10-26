#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${MAESTRO_QUALIFICATION_STATE_SCHEMA:?}"
[[ $# == 1 ]] || { echo 'Usage: maestro-ci-validate-state STATE.json' >&2; exit 2; }
exec check-jsonschema --schemafile "$MAESTRO_QUALIFICATION_STATE_SCHEMA" "$1" >&2
