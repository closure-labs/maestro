#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
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
