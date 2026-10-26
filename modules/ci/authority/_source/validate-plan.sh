#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${MAESTRO_CI_PLAN_SCHEMA:?MAESTRO_CI_PLAN_SCHEMA must point to the route plan schema}"
plan=${1:?Usage: maestro-ci-validate-plan PLAN.json}

check-jsonschema --quiet --schemafile "$MAESTRO_CI_PLAN_SCHEMA" "$plan"
