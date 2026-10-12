#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
[[ $# -ge 1 && $# -le 2 && $1 =~ ^[1-9][0-9]*$ ]] || {
  echo 'Usage: maestro-ci-trusted-run RUN_ID [SOURCE_SHA]' >&2; exit 2;
}
[[ -z ${2:-} || $2 =~ ^[0-9a-f]{40}$ ]] || exit 2
github_cli=${GH_BIN:-gh}
metadata=$("$github_cli" api "repos/$GITHUB_REPOSITORY/actions/runs/$1")
jq -e --arg repository "$GITHUB_REPOSITORY" --arg sha "${2:-}" --argjson run "$1" '
  .id == $run and .status == "completed" and .conclusion == "success" and
  .head_repository.full_name == $repository and .head_branch == "main" and
  .path == ".github/workflows/ci.yml" and
  (.event | IN("push", "schedule", "workflow_dispatch")) and
  (.head_sha | test("^[0-9a-f]{40}$")) and
  ($sha == "" or .head_sha == $sha)
' <<<"$metadata" >/dev/null
branch=$("$github_cli" api "repos/$GITHUB_REPOSITORY/branches/main")
jq -e '.protected == true and (.commit.sha | test("^[0-9a-f]{40}$"))' <<<"$branch" >/dev/null
source_sha=$(jq -er .head_sha <<<"$metadata")
main_sha=$(jq -er .commit.sha <<<"$branch")
comparison=$("$github_cli" api "repos/$GITHUB_REPOSITORY/compare/$source_sha...$main_sha")
jq -e --arg sha "$source_sha" '.merge_base_commit.sha == $sha' <<<"$comparison" >/dev/null
printf '%s\n' "$metadata"
