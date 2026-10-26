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

audit_started=$(date +%s)
audit_phase=inventory-preflight
audit_summary() {
  local status=$?
  if [[ -n ${MAESTRO_CI_AUDIT_TIMINGS:-} ]]; then
    jq -n --arg phase "$audit_phase" --argjson exitCode "$status" \
      --argjson elapsedSeconds "$(( $(date +%s) - audit_started ))" \
      '{schemaVersion:1,phase:$phase,exitCode:$exitCode,elapsedSeconds:$elapsedSeconds}' \
      >"${MAESTRO_CI_AUDIT_TIMINGS%.json}.summary.json"
  fi
}
trap audit_summary EXIT
if [[ -n ${MAESTRO_CI_AUDIT_TIMINGS:-} ]]; then
  mkdir -p "$(dirname "$MAESTRO_CI_AUDIT_TIMINGS")"
fi
MAESTRO_SYSTEM_ROOT="$repo_root" maestro-ci-security-inventory-preflight
audit_phase=flake-evaluation
nix flake check --accept-flake-config --no-build --print-build-logs \
  "$flake_ref" "$@"
manifest_args=()
if [[ -n ${MAESTRO_CI_AUDIT_MANIFEST:-} ]]; then
  manifest_args=(--manifest "$MAESTRO_CI_AUDIT_MANIFEST")
fi
if [[ -n ${MAESTRO_CI_AUDIT_TIMINGS:-} ]]; then
  manifest_args+=(--timings "$MAESTRO_CI_AUDIT_TIMINGS")
fi
audit_phase=validation-targets
flake-plan-runner \
  --flake "$flake_ref" \
  --plan "${MAESTRO_CI_VALIDATION_PLAN:-lib.ciPlans.x86_64-linux.validation}" \
  "${manifest_args[@]}"
