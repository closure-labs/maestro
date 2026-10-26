#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${MAESTRO_SYSTEM_ROOT:-}
if [[ -z "$repo_root" ]]; then
  repo_root=$(git rev-parse --show-toplevel)
fi
policy=${MAESTRO_INSTALLER_POLICY:-$repo_root/modules/ci/graph/_source/installer-policy.json}

jq -e '
  (.alwaysRelevantPatterns | type == "array") and
  all(.alwaysRelevantPatterns[]; type == "string" and length > 0) and
  (.ignoredChangePatterns | type == "array") and
  all(.ignoredChangePatterns[]; type == "string" and length > 0)
' "$policy" >/dev/null
mapfile -t always_relevant_patterns < <(jq -r '.alwaysRelevantPatterns[]' "$policy")
mapfile -t ignored_patterns < <(jq -r '.ignoredChangePatterns[]' "$policy")

path_is_relevant() {
  local path=$1
  local pattern

  for pattern in "${always_relevant_patterns[@]}"; do
    # Policy entries are intentionally interpreted as shell glob patterns.
    # shellcheck disable=SC2053
    if [[ "$path" == $pattern ]]; then
      return 0
    fi
  done
  for pattern in "${ignored_patterns[@]}"; do
    # Policy entries are intentionally interpreted as shell glob patterns.
    # shellcheck disable=SC2053
    if [[ "$path" == $pattern ]]; then
      return 1
    fi
  done
  return 0
}

if [[ ${1:-} == --filter-index ]]; then
  while IFS= read -r -d '' index_entry; do
    path=${index_entry#*$'\t'}
    if path_is_relevant "$path"; then
      printf '%s\0' "$index_entry"
    fi
  done
  exit 0
fi
if (($# > 0)); then
  printf 'Usage: maestro-ci-classify-paths [--filter-index]\n' >&2
  exit 2
fi

required=false
while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  if path_is_relevant "$path"; then
    required=true
    break
  fi
done
printf '%s\n' "$required"
