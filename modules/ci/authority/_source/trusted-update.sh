#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${PR_NUMBER:?PR_NUMBER must be set}"
: "${EXPECTED_BRANCH:?EXPECTED_BRANCH must be set}"
: "${EXPECTED_TITLE:?EXPECTED_TITLE must be set}"
: "${EXPECTED_AUTHOR:?EXPECTED_AUTHOR must be set}"
: "${DEFAULT_BRANCH:?DEFAULT_BRANCH must be set}"

ci_workflow=${CI_WORKFLOW:-ci.yml}
wait_for_merge=${WAIT_FOR_MERGE:-false}
expected_change_kind=${EXPECTED_CHANGE_KIND:?EXPECTED_CHANGE_KIND must be explicitly allowlisted}
ci_poll_interval=${CI_POLL_INTERVAL:-5}

read_pr() {
  gh pr view "$PR_NUMBER" \
    --repo "$GITHUB_REPOSITORY" \
    --json id,author,baseRefName,headRefName,headRefOid,headRepository,mergeCommit,mergeStateStatus,state,title,url
}

validate_pr() {
  local candidate=$1
  local author

  author=$(jq -er .author.login <<<"$candidate")
  author=${author#app/}
  [[ $(jq -er .state <<<"$candidate") == OPEN ]]
  [[ $(jq -er .title <<<"$candidate") == "$EXPECTED_TITLE" ]]
  [[ "$author" == "$EXPECTED_AUTHOR" ]]
  [[ $(jq -er .baseRefName <<<"$candidate") == "$DEFAULT_BRANCH" ]]
  [[ $(jq -er .headRepository.nameWithOwner <<<"$candidate") == "$GITHUB_REPOSITORY" ]]
  [[ $(jq -er .headRefName <<<"$candidate") == "$EXPECTED_BRANCH" ]]
}

validate_changes() {
  local candidate=$1
  local head_sha
  local -a changed_files

  case "$expected_change_kind" in
    cargo | flake-lock | version)
      mapfile -t changed_files < <(
        gh api --paginate \
          "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100" \
          --jq '.[].filename'
      )
      ;;
    *)
      printf 'Unknown trusted change kind: %s\n' "$expected_change_kind" >&2
      return 1
      ;;
  esac

  if [[ "$expected_change_kind" == cargo ]]; then
    [[ ${#changed_files[@]} -ge 1 && ${#changed_files[@]} -le 2 ]]
    for changed_file in "${changed_files[@]}"; do
      case "$changed_file" in
        modules/features/operator/menu/_source/frontend/Cargo.toml | modules/features/operator/menu/_source/frontend/Cargo.lock) ;;
        *) return 1 ;;
      esac
    done
    return
  fi

  if [[ "$expected_change_kind" == flake-lock ]]; then
    [[ ${#changed_files[@]} -ge 1 && ${#changed_files[@]} -le 2 ]]
    for changed_file in "${changed_files[@]}"; do
      case "$changed_file" in
        devenv.lock | flake.lock) ;;
        *) return 1 ;;
      esac
    done
    return
  fi

  : "${EXPECTED_VERSION:?EXPECTED_VERSION must be set for version changes}"
  [[ ${#changed_files[@]} -eq 1 ]]
  [[ ${changed_files[0]} == VERSION ]]
  head_sha=$(jq -er .headRefOid <<<"$candidate")
  [[ $(gh api \
    -H 'Accept: application/vnd.github.raw+json' \
    "repos/${GITHUB_REPOSITORY}/contents/VERSION?ref=${head_sha}") == "$EXPECTED_VERSION" ]]
}

pr=$(read_pr)
validate_pr "$pr"
validate_changes "$pr"
head_sha=$(jq -er .headRefOid <<<"$pr")
default_sha=$(gh api \
  "repos/${GITHUB_REPOSITORY}/commits/${DEFAULT_BRANCH}" \
  --jq .sha)
merge_base_sha=$(gh api \
  "repos/${GITHUB_REPOSITORY}/compare/${default_sha}...${head_sha}" \
  --jq .merge_base_commit.sha)
if [[ "$merge_base_sha" != "$default_sha" ]]; then
  previous_head_sha=$head_sha
  gh pr update-branch "$PR_NUMBER" --repo "$GITHUB_REPOSITORY"
  for _ in {1..24}; do
    pr=$(read_pr)
    validate_pr "$pr"
    validate_changes "$pr"
    head_sha=$(jq -er .headRefOid <<<"$pr")
    [[ "$head_sha" == "$previous_head_sha" ]] || break
    sleep "$ci_poll_interval"
  done
  [[ "$head_sha" != "$previous_head_sha" ]] || {
    printf 'Timed out waiting for trusted update %s to refresh its head.\n' "$PR_NUMBER" >&2
    exit 1
  }
fi
branch=$(jq -er .headRefName <<<"$pr")
head_sha=$(jq -er .headRefOid <<<"$pr")
pr_url=$(jq -er .url <<<"$pr")

run_id=
dispatched=false
for attempt in {1..6}; do
  pull_runs=$(
    for event in pull_request workflow_dispatch; do
      gh run list \
        --repo "$GITHUB_REPOSITORY" \
        --workflow "$ci_workflow" \
        --event "$event" \
        --branch "$branch" \
        --commit "$head_sha" \
        --limit 5 \
        --json conclusion,databaseId,headSha
    done | jq -s add
  )
  run_id=$(jq -r --arg sha "$head_sha" \
    'first(.[] | select(.headSha == $sha and .conclusion != "action_required") | .databaseId) // empty' \
    <<<"$pull_runs")
  [[ -z "$run_id" ]] || break
  approval_run_id=$(jq -r --arg sha "$head_sha" \
    'first(.[] | select(.headSha == $sha and .conclusion == "action_required") | .databaseId) // empty' \
    <<<"$pull_runs")
  if [[ -n "$approval_run_id" ]]; then
    gh api --method POST \
      "repos/${GITHUB_REPOSITORY}/actions/runs/${approval_run_id}/approve" \
      >/dev/null
    run_id=$approval_run_id
    break
  fi
  if [[ $dispatched == false && $attempt -ge 2 ]]; then
    gh workflow run "$ci_workflow" \
      --repo "$GITHUB_REPOSITORY" \
      --ref "$branch"
    dispatched=true
  fi
  sleep "$ci_poll_interval"
done

[[ -n "$run_id" ]] || {
  printf 'Could not locate pull-request CI for trusted update %s.\n' "$PR_NUMBER" >&2
  exit 1
}
if [[ "$wait_for_merge" == true ]]; then
  # These callers already wait for merge. Acquire successful exact-head CI
  # before the final allowlist check and protected queue request.
  gh run watch "$run_id" --repo "$GITHUB_REPOSITORY" --interval 30 --exit-status
fi
pr=$(read_pr)
if [[ "$wait_for_merge" == true && $(jq -er .state <<<"$pr") == MERGED ]]; then
  [[ $(jq -er .headRefOid <<<"$pr") == "$head_sha" ]]
  jq -er .mergeCommit.oid <<<"$pr"
  exit 0
fi
validate_pr "$pr"
validate_changes "$pr"
[[ $(jq -er .headRefOid <<<"$pr") == "$head_sha" ]] || {
  echo 'Trusted update head changed while locating CI; retry validation.' >&2; exit 1;
}
# Queue admission needs a personal token so GitHub emits merge_group checks.
# Keep reads, branch updates and CI dispatches on the job's GITHUB_TOKEN.
: "${MERGE_QUEUE_TOKEN:?MERGE_QUEUE_TOKEN must be configured for protected queue admission}"
GH_TOKEN="$MERGE_QUEUE_TOKEN" gh pr merge \
  --repo "$GITHUB_REPOSITORY" \
  --auto \
  --merge \
  --match-head-commit "$head_sha" \
  "$pr_url"

enqueue_if_ready() {
  local queue_state current_pr queued
  # GraphQL variables are supplied separately and must stay literal here.
  # shellcheck disable=SC2016
  queue_state=$(gh api graphql -f query='
    query($id: ID!) {
      node(id: $id) { ... on PullRequest { id headRefOid isInMergeQueue mergeStateStatus } }
    }' -f id="$(jq -er .id <<<"$pr")")
  jq -e --arg head "$head_sha" '.data.node.headRefOid == $head' <<<"$queue_state" >/dev/null
  if [[ $(jq -r .data.node.isInMergeQueue <<<"$queue_state") == true ||
        $(jq -r .data.node.mergeStateStatus <<<"$queue_state") != CLEAN ]]; then
    return
  fi
  current_pr=$(read_pr)
  [[ $(jq -er .headRefOid <<<"$current_pr") == "$head_sha" ]]
  if [[ $(jq -er .state <<<"$current_pr") == MERGED ]]; then
    return
  fi
  validate_pr "$current_pr"
  validate_changes "$current_pr"
  # Enabling auto-merge is not proof of queue membership. Use the protected
  # enqueue operation, preserving atomic head binding and the normal queue CI.
  # shellcheck disable=SC2016
  queued=$(GH_TOKEN="$MERGE_QUEUE_TOKEN" gh api graphql -f query='
    mutation($id: ID!, $head: GitObjectID!) {
      enqueuePullRequest(input: {pullRequestId: $id, expectedHeadOid: $head}) {
        mergeQueueEntry { id pullRequest { id headRefOid } }
      }
    }' -f id="$(jq -er .id <<<"$current_pr")" -f head="$head_sha")
  jq -e --arg id "$(jq -er .id <<<"$current_pr")" --arg head "$head_sha" '
    .data.enqueuePullRequest.mergeQueueEntry as $entry |
    ($entry.id | type == "string" and length > 0) and
    $entry.pullRequest.id == $id and $entry.pullRequest.headRefOid == $head
  ' <<<"$queued" >/dev/null
}

# The asynchronous queue helper must also turn a green auto-merge request into
# an actual queue entry; pending checks return immediately without watching.
enqueue_if_ready

if [[ "$wait_for_merge" == true ]]; then
  for _ in {1..240}; do
    state=$(gh pr view "$PR_NUMBER" \
      --repo "$GITHUB_REPOSITORY" \
      --json headRefOid,mergeCommit,state)
    [[ $(jq -er .headRefOid <<<"$state") == "$head_sha" ]]
    if [[ $(jq -r .state <<<"$state") == MERGED ]]; then
      jq -er .mergeCommit.oid <<<"$state"
      exit 0
    fi
    # GitHub may still be recomputing CLEAN after CI completes. Recheck during
    # the existing bounded wait instead of leaving an auto-merge request idle.
    enqueue_if_ready
    sleep 30
  done
  printf 'Timed out waiting for trusted update %s to merge.\n' "$PR_NUMBER" >&2
  exit 1
fi
