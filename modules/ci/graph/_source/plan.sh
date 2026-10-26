#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
cd "$repo_root"
output=${MAESTRO_GRAPH_OUTPUT:-ci-graph}
mkdir -p "$output"
started=$(date +%s)
candidate=${GITHUB_SHA:-$(git rev-parse HEAD)}
[[ $candidate =~ ^[0-9a-f]{40}$ && $(git rev-parse HEAD) == "$candidate" ]]
base=${MERGE_BASE_SHA:-${PR_BASE_SHA:-${PUSH_BASE_SHA:-}}}
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-graph.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
# Evaluate immutable source archives. A moving bookmark can never be a candidate.
mkdir -p "$work/candidate"
git archive "$candidate" | tar -x -C "$work/candidate"
if ! nix eval --accept-flake-config --no-write-lock-file --json \
  "path:$work/candidate#lib.ciGraph.x86_64-linux" >"$output/candidate.json" 2>"$output/candidate-evaluation.log"; then
  printf 'null\n' >"$output/candidate.json"
fi
args=()
if [[ -n ${CI_PLAN:-} ]]; then
  printf '%s\n' "$CI_PLAN" >"$output/route.json"
  args+=(--route-plan "$output/route.json")
fi
if [[ $base =~ ^[0-9a-f]{40}$ ]] && git cat-file -e "$base^{commit}"; then
  mkdir -p "$work/base"
  git archive "$base" | tar -x -C "$work/base"
  if nix eval --accept-flake-config --no-write-lock-file --json \
    "path:$work/base#lib.ciGraph.x86_64-linux" >"$output/base.json" 2>"$output/base-evaluation.log"; then
    args+=(--base "$output/base.json")
  else
    printf 'null\n' >"$output/base.json"
  fi
  git diff --name-only "$base" "$candidate" >"$output/changed-inputs.txt"
  args+=(--base-revision "$base" --changed-inputs "$output/changed-inputs.txt")
fi
[[ ${FORCE_BUILD:-false} != true ]] || args+=(--force)
[[ ${GRAPH_FORK:-false} != true ]] || args+=(--fork)
if [[ $(jq -r '.schemaVersion // 0' "$output/candidate.json") == 1 ]]; then
  mapfile -t derivations < <(jq -r '.targets[].derivation' "$output/candidate.json" | sort -u)
  nix derivation show "${derivations[@]}" | jq '
    (if has("derivations") then
      if .version == 4 then .derivations else error("Unknown derivation JSON envelope") end
    else . end) | with_entries(.value |= {outputs,inputDrvs:(if .version == 4 then .inputs.drvs else .inputDrvs end)})' >"$output/derivations.json"
  args+=(--derivations "$output/derivations.json")
fi
maestro-ci-graph "$output/candidate.json" --revision "$candidate" "${args[@]}" >"$output/plan.json"
maestro-ci-graph "$output/candidate.json" --ownership >"$output/ownership.md" || printf 'Graph unavailable; complete validation required.\n' >"$output/ownership.md"
# This output authenticates the graph artifact within this workflow attempt.
if [[ $(jq -r '.schemaVersion // 0' "$output/candidate.json") == 1 ]]; then
  diff -u docs/feature-outputs.md "$output/ownership.md"
fi
manifest_sha=$(sha256sum "$output/plan.json" | cut -d' ' -f1)
if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  printf 'manifest_sha256=%s\n' "$manifest_sha" >>"$GITHUB_OUTPUT"
fi
jq -n --argjson elapsedSeconds "$(( $(date +%s) - started ))" \
  '{schemaVersion:1,stage:"graph-planning",elapsedSeconds:$elapsedSeconds}' >"$output/timings.json"
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  {
    printf '### CI derivation comparison (shadow mode)\n\n'
    jq -r '"Candidate: `\(.candidateRevision)`\n\nBase: `\(.baseRevision)`\n\nChanged derivations: \(.changedDerivations|length); equal derivations: \(.equalDerivations|length). All twenty audit obligations remain required. Equality alone grants no evidence reuse.\n\nFallback reasons: \(.fallbackReasons|join(", "))\n"' "$output/plan.json"
    printf '\nChanged inputs:\n\n'
    jq -r '.changedInputs[]? | "- `\(.)`"' "$output/plan.json"
    printf '\nChanged derivations:\n\n'
    jq -r '.changedDerivations[] | "- `\(.)`"' "$output/plan.json"
    cat "$output/ownership.md"
  } >>"$GITHUB_STEP_SUMMARY"
fi
