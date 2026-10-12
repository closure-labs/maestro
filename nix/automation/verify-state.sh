#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: maestro-ci-verify-state STATE.json RUN_ID' >&2; exit 2; }
: "${GITHUB_REPOSITORY:?}"
maestro-ci-validate-state "$1"
source_sha=$(jq -er .source_commit "$1")
maestro-ci-trusted-run "$2" "$source_sha" >/dev/null
"${GH_BIN:-gh}" attestation verify "$1" --repo "$GITHUB_REPOSITORY" \
  --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/ci.yml" \
  --source-ref refs/heads/main --source-digest "$source_sha" --signer-digest "$source_sha" \
  --deny-self-hosted-runners >/dev/null
