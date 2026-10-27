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
# Dispatch/schedule comparisons use the candidate's immutable first parent.
# Never resolve a moving branch name to manufacture a comparison base.
if [[ -z "$base" && ${GITHUB_EVENT_NAME:-} =~ ^(workflow_dispatch|schedule)$ ]]; then
  base=$(git rev-parse --verify "$candidate^" 2>/dev/null) || base=
fi
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-graph.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
# Evaluate immutable source archives. A moving bookmark can never be a candidate.
mkdir -p "$work/candidate"
git archive "$candidate" | tar -x -C "$work/candidate"
if ! nix eval --accept-flake-config --no-write-lock-file --json \
  "path:$work/candidate#lib.ciGraph.x86_64-linux" >"$output/candidate.json" 2>"$output/candidate-evaluation.log"; then
  cat "$output/candidate-evaluation.log" >&2
  printf 'Candidate graph evaluation failed; no product jobs may consume it.\n' >&2
  exit 1
fi
# A missing/unsupported base selects complete qualification. An invalid candidate
# cannot describe exact transports and must fail planning before any product work.
maestro-ci-graph "$output/candidate.json" >"$output/validation.json"
args=()
if [[ -n ${CI_PLAN:-} ]]; then
  printf '%s\n' "$CI_PLAN" >"$output/route.json"
  args+=(--route-plan "$output/route.json")
else
  printf 'null\n' >"$output/route.json"
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
if [[ ${GITHUB_EVENT_NAME:-} == workflow_dispatch && ${VALIDATE_ONLY:-false} == true &&
      ${FORCE_BUILD:-false} != true && ${FORCE_ARTIFACT:-false} != true ]]; then
  args+=(--validate-only)
fi
if [[ $(jq -r '.schemaVersion // 0' "$output/candidate.json") == 1 ]]; then
  mapfile -t derivations < <(jq -r '.targets[].derivation' "$output/candidate.json" | sort -u)
  nix derivation show "${derivations[@]}" | jq '
    (if has("derivations") then
      if .version == 4 then .derivations else error("Unknown derivation JSON envelope") end
    else . end) | with_entries(.value |= {outputs,inputDrvs:(if .version == 4 then .inputs.drvs else .inputDrvs end)})' >"$output/derivations.json"
  args+=(--derivations "$output/derivations.json")
fi
maestro-ci-graph "$output/candidate.json" --revision "$candidate" "${args[@]}" >"$output/plan.json"
if [[ $(jq -r '.completeQualificationRequired' "$output/plan.json") == true ]] &&
   ! jq -e '.schema_version == 4 and .qualification.required == true and
     .qualification.mode == "qualify-media" and .retained_evidence == null' "$output/route.json" >/dev/null; then
  # Re-run native routing so its plan AND qualification pointer agree.
  # Editing a mode string would retain another producer's bindings.
  FORCE_BUILD=true FORCE_ARTIFACT=true ALLOW_REUSE=false \
    GITHUB_OUTPUT="$work/fallback-outputs" MAESTRO_CI_ROUTE_OUTPUT="$output/route.json" \
    maestro-ci-route >"$output/fallback-routing.log"
  jq -e '.schema_version == 4 and .qualification.required == true and
    .qualification.mode == "qualify-media" and .retained_evidence == null' "$output/route.json" >/dev/null
  while IFS= read -r reason; do
    args+=(--routing-fallback-reason "$reason")
  done < <(jq -r '.fallbackReasons[]' "$output/plan.json")
  args+=(--route-regenerated)
  maestro-ci-graph "$output/candidate.json" --revision "$candidate" "${args[@]}" >"$output/plan.json"
fi
maestro-ci-graph "$output/candidate.json" --ownership >"$output/ownership.md" || printf 'Graph unavailable; complete validation required.\n' >"$output/ownership.md"
# This output authenticates the graph artifact within this workflow attempt.
if [[ $(jq -r '.schemaVersion // 0' "$output/candidate.json") == 1 ]]; then
  diff -u docs/feature-outputs.md "$output/ownership.md"
fi
manifest_sha=$(sha256sum "$output/plan.json" | cut -d' ' -f1)
if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  {
    printf 'manifest_sha256=%s\n' "$manifest_sha"
    printf 'route_plan=%s\n' "$(jq -c . "$output/route.json")"
    printf 'job_plan=%s\n' "$(jq -c .decisions.jobs "$output/plan.json")"
    printf 'gating_enabled=%s\n' "$(jq -r .gatingEnabled "$output/plan.json")"
    printf 'scheduling_mode=%s\n' "$(jq -r .mode "$output/plan.json")"
  } >>"$GITHUB_OUTPUT"
fi
jq -n --argjson elapsedSeconds "$(( $(date +%s) - started ))" \
  '{schemaVersion:1,stage:"graph-planning",elapsedSeconds:$elapsedSeconds}' >"$output/timings.json"
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  {
    printf '### CI derivation comparison (%s)\n\n' "$(jq -r .mode "$output/plan.json")"
    jq -r '"Candidate: `\(.candidateRevision)`\n\nBase: `\(.baseRevision)`\n\nChanged derivations: \(.changedDerivations|length); equal derivations: \(.equalDerivations|length). All twenty audit obligations remain required. Equality alone grants no evidence reuse.\n\nFallback reasons: \(.fallbackReasons|join(", "))\n"' "$output/plan.json"
    printf '\nChanged inputs:\n\n'
    jq -r '.changedInputs[]? | "- `\(.)`"' "$output/plan.json"
    printf '\nChanged derivations:\n\n'
    jq -r '.changedDerivations[] | "- `\(.)`"' "$output/plan.json"
    cat "$output/ownership.md"
  } >>"$GITHUB_STEP_SUMMARY"
fi
