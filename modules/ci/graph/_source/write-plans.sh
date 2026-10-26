#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "${MAESTRO_SYSTEM_ROOT:-$PWD}"
flake_ref="path:$PWD"
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  flake_ref="git+file:$PWD?shallow=1"
fi
output=$(mktemp "${TMPDIR:-/tmp}/maestro-plans.XXXXXX")
trap 'rm -f -- "$output"' EXIT
nix eval --accept-flake-config --no-write-lock-file --json \
  "$flake_ref#lib.ciPlans.x86_64-linux" \
  --apply 'plans: builtins.mapAttrs (_: plan: {inherit (plan) name targets;}) plans' |
  jq -S . >"$output"
install -m 0644 "$output" modules/ci/graph/_lib/plans.json
