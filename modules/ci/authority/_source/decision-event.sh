#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# This unprivileged collector deliberately emits no candidate-controlled data.
# The trusted authority job resolves the event again through the GitHub API.
case ${GITHUB_EVENT_NAME:?} in
  pull_request|pull_request_review|merge_group) ;;
  *) echo 'Unsupported authority event' >&2; exit 2 ;;
esac
