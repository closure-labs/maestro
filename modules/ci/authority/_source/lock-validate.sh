#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
flake_lock=${1:-$repo_root/flake.lock}
devenv_lock=${2:-$repo_root/devenv.lock}

jq -e '.version >= 7 and .nodes.root.inputs.nixpkgs and .nodes.root.inputs.devenv' \
  "$flake_lock" >/dev/null
jq -e '.nodes.root.inputs.nixpkgs and .nodes.root.inputs.devenv' \
  "$devenv_lock" >/dev/null

locked_identity() {
  local lock=$1
  local input=$2
  jq -cer --arg input "$input" '
    .nodes[.nodes.root.inputs[$input]].locked |
    {type, rev, narHash}
  ' "$lock"
}

for input in nixpkgs devenv; do
  flake_identity=$(locked_identity "$flake_lock" "$input")
  devenv_identity=$(locked_identity "$devenv_lock" "$input")
  if [[ "$flake_identity" != "$devenv_identity" ]]; then
    printf '%s is not synchronized across flake.lock and devenv.lock.\n' "$input" >&2
    printf 'flake.lock:  %s\n' "$flake_identity" >&2
    printf 'devenv.lock: %s\n' "$devenv_identity" >&2
    exit 1
  fi
done

printf 'flake.lock and devenv.lock share the same nixpkgs and devenv pins.\n'
