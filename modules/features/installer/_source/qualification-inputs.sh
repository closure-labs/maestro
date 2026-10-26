#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${MAESTRO_SYSTEM_ROOT:-}
if [[ -z "$repo_root" ]]; then
  repo_root=$(git rev-parse --show-toplevel)
fi
system=${MAESTRO_CI_SYSTEM:-x86_64-linux}
graph=$(nix eval --accept-flake-config --json \
  "path:${repo_root}#lib.ciQualificationInputs.${system}")
jq -e 'type == "object" and (.media | type == "object") and (.evidence | type == "object")' \
  <<<"$graph" >/dev/null

media_input=$(jq -cS .media <<<"$graph" | sha256sum | cut -d' ' -f1)
evidence_input=$(jq -cS .evidence <<<"$graph" | sha256sum | cut -d' ' -f1)

jq -cn \
  --arg media_input "$media_input" \
  --arg evidence_input "$evidence_input" \
  '{schema_version:1,media_input:$media_input,evidence_input:$evidence_input}'
