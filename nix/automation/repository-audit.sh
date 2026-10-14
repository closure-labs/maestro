#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Audit every repository contract declared by the flake's validation plan.

repo_root="${MAESTRO_SYSTEM_ROOT:-}"
if [[ -z $repo_root ]]; then
  if git_root=$(git rev-parse --show-toplevel 2>/dev/null); then
    repo_root=$git_root
  else
    repo_root=$PWD
  fi
fi

flake_ref="path:$repo_root"
if git -C "$repo_root" rev-parse --show-toplevel >/dev/null 2>&1; then
  flake_ref="git+file:$repo_root"
fi

MAESTRO_SYSTEM_ROOT="$repo_root" maestro-ci-security-inventory-preflight
nix flake check --accept-flake-config --no-build --print-build-logs \
  "$flake_ref" "$@"
manifest_args=()
if [[ -n ${MAESTRO_CI_AUDIT_MANIFEST:-} ]]; then
  manifest_args=(--manifest "$MAESTRO_CI_AUDIT_MANIFEST")
fi
exec flake-plan-runner \
  --flake "$flake_ref" \
  --plan "${MAESTRO_CI_VALIDATION_PLAN:-lib.ciPlans.x86_64-linux.validation}" \
  "${manifest_args[@]}"
