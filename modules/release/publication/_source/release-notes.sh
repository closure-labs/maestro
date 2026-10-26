#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

version=${1:?usage: release-notes.sh VERSION [CHANGELOG]}
changelog=${2:-CHANGELOG.md}

[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  printf 'Invalid release version: %s\n' "${version}" >&2
  exit 1
}
[[ -r "${changelog}" ]] || {
  printf 'Cannot read changelog: %s\n' "${changelog}" >&2
  exit 1
}

awk -v heading="## [${version}] - " '
  index($0, heading) == 1 {
    found = 1
    copying = 1
    next
  }
  copying && /^## / {
    exit
  }
  copying {
    print
    if ($0 !~ /^[[:space:]]*$/) content = 1
  }
  END {
    if (!found || !content) exit 1
  }
' "${changelog}" || {
  printf 'No non-empty changelog entry found for %s.\n' "${version}" >&2
  exit 1
}
