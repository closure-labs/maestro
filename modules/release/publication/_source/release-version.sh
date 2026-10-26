#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

base_version=${1:?usage: release-version.sh BASE_VERSION BUMP}
requested_bump=${2:?usage: release-version.sh BASE_VERSION BUMP}
if [[ "$base_version" =~ ^[0-9]+\.[0-9]+$ ]]; then
  base_version="${base_version}.0"
fi
[[ "$base_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  printf 'Invalid base version: %s\n' "$base_version" >&2
  exit 2
}

release_log=$(cat)
selected_bump=$requested_bump
if [[ "$selected_bump" == auto ]]; then
  if grep -Eq '(^[[:alnum:]-]+(\([^)]*\))?!:)|(^BREAKING[ -]CHANGE:)' <<<"$release_log"; then
    selected_bump="major"
  elif grep -Eq '^feat(\([^)]*\))?:' <<<"$release_log"; then
    selected_bump="minor"
  else
    selected_bump="patch"
  fi
fi

IFS=. read -r major minor patch <<<"$base_version"
case "$selected_bump" in
  major) version="$((major + 1)).0.0" ;;
  minor) version="${major}.$((minor + 1)).0" ;;
  patch) version="${major}.${minor}.$((patch + 1))" ;;
  *)
    printf 'Unsupported release bump: %s\n' "$selected_bump" >&2
    exit 2
    ;;
esac

printf '%s\t%s\n' "$version" "$selected_bump"
