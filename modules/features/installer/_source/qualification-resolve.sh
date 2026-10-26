#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ ${MAESTRO_RESOLVE_BOUNDED:-false} != true ]]; then
  temporary=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-resolve.XXXXXX")
  trap 'rm -rf -- "$temporary"' EXIT
  status=0
  MAESTRO_RESOLVE_BOUNDED=true RUNNER_TEMP="$temporary" \
    python3 "$MAESTRO_OPERATIONS_SOURCE" --timeout 300 -- bash "$0" "$@" || status=$?
  if [[ $status == 124 ]]; then
    printf 'Optional qualification discovery timed out; qualifying normally.\n' >&2
    ALLOW_REUSE=false MAESTRO_RESOLVE_BOUNDED=true bash "$0" "$@"
    exit 0
  fi
  exit "$status"
fi

gh() {
  local limit=30
  if [[ ${1:-} == run && ${2:-} == download ]]; then
    limit=90
    for argument in "$@"; do
      [[ $argument == maestro-evidence ]] && limit=180
    done
  fi
  python3 "$MAESTRO_OPERATIONS_SOURCE" --timeout "$limit" -- gh "$@"
}

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID must be set}"
: "${GITHUB_SHA:?GITHUB_SHA must be set}"

workflow=${CI_WORKFLOW:-ci.yml}
allow_reuse=${ALLOW_REUSE:-true}
force_build=${FORCE_BUILD:-false}
runner_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
inputs=$(maestro-ci-qualification-inputs)
media_input=$(jq -er .media_input <<<"$inputs")
evidence_input=$(jq -er .evidence_input <<<"$inputs")

mode=qualify-media
artifact_run_id=$GITHUB_RUN_ID
media_run_id=$GITHUB_RUN_ID
evidence_run_id=$GITHUB_RUN_ID
state_evidence_run_id=$GITHUB_RUN_ID
artifact_source_commit=$GITHUB_SHA
media_source_commit=$GITHUB_SHA
producer_event=${GITHUB_EVENT_NAME:-workflow_dispatch}

preimport_deadline=${CI_OPERATION_DEADLINE:-$(python3 -c 'import time; print(time.monotonic() + 300)')}
discovery_deadline=$(python3 -c 'import time; print(time.monotonic() + 90)')
export CI_OPERATION_DEADLINE
CI_OPERATION_DEADLINE=$(python3 -c 'import sys; print(min(map(float, sys.argv[1:])))' "$preimport_deadline" "$discovery_deadline")
optional_payload_downloaded=false

media_candidate_run_id=
media_candidate_source_commit=
evidence_candidate_run_id=

artifact_available() {
  local run_id=$1
  local artifact_name=$2
  gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/artifacts" --jq ".artifacts[] | select(.name == \"${artifact_name}\" and (.expired | not)) | .id" |
    head -n 1
}

run_is_trusted() {
  maestro-ci-trusted-run "$1" "${2:-}" >/dev/null
}

verify_evidence_artifact() {
  local evidence_dir=$1
  local expected_run_id=$2
  local state_file="$evidence_dir/maestro-qualification-state.json"
  maestro-ci-verify-state "$state_file" "$expected_run_id" || return 1
  maestro-ci-verify-inventory "$evidence_dir" "$(jq -er .artifact_source_commit "$state_file")" evidence || return 1
  jq -e --arg evidence_input "$evidence_input" --argjson evidence_run_id "$expected_run_id" '
    .evidence_input == $evidence_input and .evidence_run_id == $evidence_run_id
  ' "$state_file" >/dev/null
}

if [[ "$allow_reuse" == true && "$force_build" != true ]]; then
  while read -r run_id; do
    [[ "$run_id" =~ ^[0-9]+$ ]] || continue
    run_is_trusted "$run_id" || continue

    state_dir=$(mktemp -d "${runner_temp}/maestro-state.XXXXXX")
    if ! gh run download "$run_id" --repo "$GITHUB_REPOSITORY" --name maestro-qualification-state --dir "$state_dir" >/dev/null 2>&1; then
      rm -rf -- "$state_dir"
      continue
    fi

    maestro-ci-verify-state "$state_dir/maestro-qualification-state.json" "$run_id" >/dev/null
    state_file="$state_dir/maestro-qualification-state.json"
    candidate_artifact_run_id=$(jq -r .artifact_run_id "$state_file")
    candidate_evidence_run_id=$(jq -r .evidence_run_id "$state_file")
    if ! jq -c '[
      {run_id:.artifact_run_id,source_sha:.artifact_source_commit},
      {run_id:.media_run_id,source_sha:.media_source_commit},
      {run_id:.evidence_run_id,source_sha:""}
    ]' "$state_file" | maestro-ci-trusted-run --batch >/dev/null; then
      rm -rf -- "$state_dir"
      continue
    fi
    candidate_media_matches=false
    candidate_evidence_matches=false

    if [[ $(jq -r .media_input "$state_file") == "$media_input" ]] &&
      [[ -n $(artifact_available "$candidate_artifact_run_id" maestro-installer) ]]; then
      candidate_media_matches=true
      if [[ -z "$media_candidate_run_id" ]]; then
        media_candidate_run_id=$candidate_artifact_run_id
        media_candidate_source_commit=$(jq -r .artifact_source_commit "$state_file")
      fi
    fi

    if [[ $optional_payload_downloaded == false && $(jq -r .evidence_input "$state_file") == "$evidence_input" ]] &&
      [[ -n $(artifact_available "$candidate_evidence_run_id" maestro-evidence) ]]; then
      optional_payload_downloaded=true
      evidence_dir=$(mktemp -d "${runner_temp}/maestro-evidence.XXXXXX")
      if CI_OPERATION_DEADLINE="$preimport_deadline" gh run download "$candidate_evidence_run_id" --repo "$GITHUB_REPOSITORY" --name maestro-evidence --dir "$evidence_dir" >/dev/null 2>&1; then
        CI_OPERATION_DEADLINE="$preimport_deadline" verify_evidence_artifact "$evidence_dir" "$candidate_evidence_run_id" || exit 2
        candidate_evidence_matches=true
        if [[ -z "$evidence_candidate_run_id" ]]; then
          evidence_candidate_run_id=$candidate_evidence_run_id
        fi
      fi
      rm -rf -- "$evidence_dir"
    fi

    if [[ "$candidate_media_matches" == true && "$candidate_evidence_matches" == true ]]; then
      mode=reuse
      artifact_run_id=$candidate_artifact_run_id
      media_run_id=$(jq -r .media_run_id "$state_file")
      evidence_run_id=$candidate_evidence_run_id
      state_evidence_run_id=$candidate_evidence_run_id
      artifact_source_commit=$(jq -r .artifact_source_commit "$state_file")
      media_source_commit=$(jq -r .media_source_commit "$state_file")
      producer_event=$(jq -r .producer_event "$state_file")
      rm -rf -- "$state_dir"
      break
    fi
    rm -rf -- "$state_dir"
    # Rebuilding evidence is preferable to exhausting optional discovery after
    # exact authenticated media is already available. An older slow run must
    # not make the outer timeout discard this verified media candidate.
    [[ -z "$media_candidate_run_id" ]] || break
  done < <(
    gh run list --repo "$GITHUB_REPOSITORY" --workflow "$workflow" --branch main --status success --limit 100 --json databaseId --jq '.[].databaseId'
  )
fi

export CI_OPERATION_DEADLINE="$preimport_deadline"
if [[ "$mode" == qualify-media ]]; then
  if [[ -n "$media_candidate_run_id" ]]; then
    mode=refresh-evidence
    media_run_id=$media_candidate_run_id
    media_source_commit=$media_candidate_source_commit
  elif [[ -n "$evidence_candidate_run_id" ]]; then
    mode=qualify-media-reuse-evidence
    evidence_run_id=$evidence_candidate_run_id
  fi
fi

jq -n --arg mode "$mode" --arg media_input "$media_input" --arg evidence_input "$evidence_input" --arg source_commit "$GITHUB_SHA" --arg artifact_source_commit "$artifact_source_commit" --arg media_source_commit "$media_source_commit" --arg producer_event "$producer_event" --argjson artifact_run_id "$artifact_run_id" --argjson media_run_id "$media_run_id" --argjson evidence_run_id "$state_evidence_run_id" '{schema_version:5,mode:$mode,media_input:$media_input,evidence_input:$evidence_input,source_commit:$source_commit,artifact_source_commit:$artifact_source_commit,media_source_commit:$media_source_commit,producer_event:$producer_event,artifact_run_id:$artifact_run_id,media_run_id:$media_run_id,evidence_run_id:$evidence_run_id}' >maestro-qualification-state.json

maestro-ci-validate-state maestro-qualification-state.json

if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  {
    printf 'mode=%s\n' "$mode"
    printf 'artifact_run_id=%s\n' "$artifact_run_id"
    printf 'media_run_id=%s\n' "$media_run_id"
    printf 'evidence_run_id=%s\n' "$evidence_run_id"
    printf 'media_input=%s\n' "$media_input"
    printf 'evidence_input=%s\n' "$evidence_input"
  } >>"$GITHUB_OUTPUT"
fi
printf 'Qualification mode %s; artifact run %s; media run %s; evidence run %s.\n' "$mode" "$artifact_run_id" "$media_run_id" "$evidence_run_id"
