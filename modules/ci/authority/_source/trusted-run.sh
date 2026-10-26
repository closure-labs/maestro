#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
batch=false
if [[ $# == 1 && $1 == --batch ]]; then
  batch=true
  # This interface accepts requests, never caller-supplied API responses or
  # prior trust decisions. All response reuse ends with this process.
  requests=$(jq -ces '
    select(length == 1) | .[0] |
    select(type == "array" and length > 0 and
    all(.[];
      type == "object" and (keys | sort) == ["run_id", "source_sha"] and
      (.run_id | type == "number" and (tostring | test("^[1-9][0-9]*$"))) and
      (.source_sha | type == "string" and (. == "" or test("^[0-9a-f]{40}$")))
    ))
  ')
else
  [[ $# -ge 1 && $# -le 2 && $1 =~ ^[1-9][0-9]*$ ]] || {
    echo 'Usage: maestro-ci-trusted-run RUN_ID [SOURCE_SHA] | --batch < REQUESTS.json' >&2; exit 2;
  }
  [[ -z ${2:-} || $2 =~ ^[0-9a-f]{40}$ ]] || exit 2
  requests=$(jq -cn --argjson run "$1" --arg sha "${2:-}" '[{run_id:$run,source_sha:$sha}]')
fi
github_cli=${GH_BIN:-gh}
declare -A metadata_by_run=() ancestry_by_sha=()
main_sha=
results=()
while IFS= read -r request; do
  run_id=$(jq -r .run_id <<<"$request")
  expected_sha=$(jq -r .source_sha <<<"$request")
  if [[ ! -v metadata_by_run[$run_id] ]]; then
    metadata_by_run[$run_id]=$("$github_cli" api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id")
  fi
  metadata=${metadata_by_run[$run_id]}
  jq -e --arg repository "$GITHUB_REPOSITORY" --arg sha "$expected_sha" --argjson run "$run_id" '
    .id == $run and .status == "completed" and .conclusion == "success" and
    .head_repository.full_name == $repository and .head_branch == "main" and
    .path == ".github/workflows/ci.yml" and
    (.event | IN("push", "schedule", "workflow_dispatch")) and
    (.head_sha | test("^[0-9a-f]{40}$")) and
    ($sha == "" or .head_sha == $sha)
  ' <<<"$metadata" >/dev/null
  if [[ -z $main_sha ]]; then
    branch=$("$github_cli" api "repos/$GITHUB_REPOSITORY/branches/main")
    jq -e '.protected == true and (.commit.sha | test("^[0-9a-f]{40}$"))' <<<"$branch" >/dev/null
    main_sha=$(jq -er .commit.sha <<<"$branch")
  fi
  source_sha=$(jq -er .head_sha <<<"$metadata")
  if [[ ! -v ancestry_by_sha[$source_sha] ]]; then
    comparison=$("$github_cli" api "repos/$GITHUB_REPOSITORY/compare/$source_sha...$main_sha")
    jq -e --arg sha "$source_sha" '.merge_base_commit.sha == $sha' <<<"$comparison" >/dev/null
    ancestry_by_sha[$source_sha]=true
  fi
  results+=("$metadata")
done < <(jq -c '.[]' <<<"$requests")
if [[ $batch == true ]]; then
  printf '%s\n' "${results[@]}" | jq -s .
else
  printf '%s\n' "${results[@]}"
fi
