#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ ${GRAPH_RESULT_REQUIRED:-false} == true || -n ${CI_RESULT_SHA256:-} ]]; then
  [[ ${CI_RESULT_SHA256:?} =~ ^[0-9a-f]{64}$ && ${CI_GRAPH_PLAN_SHA256:?} =~ ^[0-9a-f]{64}$ ]]
  [[ $(sha256sum ci-result.json | cut -d' ' -f1) == "$CI_RESULT_SHA256" ]]
  jq -e --arg revision "${GITHUB_SHA:?}" --arg run "${GITHUB_RUN_ID:?}" --arg attempt "${GITHUB_RUN_ATTEMPT:?}" \
    --arg graph_plan "$CI_GRAPH_PLAN_SHA256" '
      .schemaVersion == 1 and .planSha256 == $graph_plan and
      .producer.GITHUB_SHA == $revision and .producer.GITHUB_RUN_ID == $run and
      .producer.GITHUB_RUN_ATTEMPT == $attempt and
      .completeValidationRequired == true and .schedulingMode == "shadow"
    ' ci-result.json >/dev/null
fi
: "${GITHUB_REF:?}" "${GITHUB_EVENT_NAME:?}" "${GITHUB_SHA:?}" "${GITHUB_REPOSITORY:?}"
[[ $GITHUB_REF == refs/heads/main && $GITHUB_SHA =~ ^[0-9a-f]{40}$ ]]
case $GITHUB_EVENT_NAME in push|schedule|workflow_dispatch) ;; *) exit 1 ;; esac
maestro-ci-validate-state maestro-qualification-state.json
[[ $(jq -er .source_commit maestro-qualification-state.json) == "$GITHUB_SHA" ]]
branch=$(gh api "repos/$GITHUB_REPOSITORY/branches/main")
jq -e '.protected == true' <<<"$branch" >/dev/null
main_sha=$(jq -er .commit.sha <<<"$branch")
comparison=$(gh api "repos/$GITHUB_REPOSITORY/compare/$GITHUB_SHA...$main_sha")
jq -e --arg sha "$GITHUB_SHA" '.merge_base_commit.sha == $sha' <<<"$comparison" >/dev/null
