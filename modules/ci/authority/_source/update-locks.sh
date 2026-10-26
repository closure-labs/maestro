#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${MAESTRO_SYSTEM_ROOT:-}
if [[ -z "$repo_root" ]]; then
  repo_root=$(git rev-parse --show-toplevel)
fi
cd "$repo_root"

nix run --accept-flake-config .#devenv -- update
nix flake update --accept-flake-config
