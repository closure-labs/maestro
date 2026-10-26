#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${UPDATE_BRANCH:?UPDATE_BRANCH must be set}"
: "${UPDATE_TITLE:?UPDATE_TITLE must be set}"
: "${UPDATE_BODY:?UPDATE_BODY must be set}"

(($# > 0)) || { echo 'usage: open-update-pr PATH...' >&2; exit 2; }
git check-ref-format --branch "$UPDATE_BRANCH" >/dev/null
[[ $UPDATE_BRANCH != main ]] || { echo 'Refusing to update main directly' >&2; exit 2; }
for path in "$@"; do
  [[ $path != /* && $path != *..* ]] || {
    printf 'Unsafe update path: %s\n' "$path" >&2
    exit 2
  }
done

if git diff --quiet -- "$@"; then
  echo 'No update changes to publish'
  exit 0
fi

git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
remote_sha=$(git ls-remote --refs origin "refs/heads/$UPDATE_BRANCH" | cut -f1)
git switch -C "$UPDATE_BRANCH"
git add -- "$@"
git diff --cached --quiet && { echo 'No allowlisted update changes to publish'; exit 0; }
git commit -m "$UPDATE_TITLE"
git push --force-with-lease="refs/heads/$UPDATE_BRANCH:$remote_sha" \
  origin "HEAD:refs/heads/$UPDATE_BRANCH"

# Reused weekly branches can have historical merged or closed PRs. A branch
# lookup may select one of those, so only edit an explicitly open PR by number.
# Keep lookup errors fatal instead of treating an API failure as an absent PR.
open_prs=$(gh pr list --repo "$GITHUB_REPOSITORY" --state open \
  --base main --head "$UPDATE_BRANCH" --limit 100 --json number,headRepository)
open_pr=$(jq -r --arg repository "$GITHUB_REPOSITORY" \
  '[.[] | select(.headRepository.nameWithOwner == $repository)] | .[0].number // empty' \
  <<<"$open_prs")
if [[ -n "$open_pr" ]]; then
  gh pr edit "$open_pr" --repo "$GITHUB_REPOSITORY" \
    --title "$UPDATE_TITLE" --body "$UPDATE_BODY"
else
  gh pr create --repo "$GITHUB_REPOSITORY" --base main --head "$UPDATE_BRANCH" \
    --title "$UPDATE_TITLE" --body "$UPDATE_BODY"
fi
