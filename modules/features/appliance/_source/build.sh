#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "${MAESTRO_SYSTEM_ROOT:-$PWD}"
[[ $(git rev-parse HEAD) == "${GITHUB_SHA:?}" ]]
flake_ref="git+file:$PWD?shallow=1&rev=$GITHUB_SHA"
export MAESTRO_NIX_EVENTS_DIR="$PWD/appliance-transfer/nix-events"
mkdir -p appliance-transfer
# Preserve native inventory decoding and approved XO/Determinate cache admission
# before realizing any appliance or standalone closure.
maestro-ci-security-inventory-preflight
nix config show substituters
nix config show trusted-public-keys
determinate_out=$(nix eval --accept-flake-config --no-write-lock-file --raw "$flake_ref#nixosConfigurations.maestro.config.nix.package.upstream.outPath")
nix path-info --store https://install.determinate.systems "$determinate_out"
xo_out=$(nix eval --accept-flake-config --no-write-lock-file --raw "$flake_ref#packages.x86_64-linux.xen-orchestra-ce.outPath")
maestro-ci-qualification-cache "$xo_out"
flake-plan-runner --flake "$flake_ref" --plan lib.ciPlans.x86_64-linux.evidence \
  --manifest appliance-transfer/evidence.json --timings appliance-transfer/evidence.timings.json
flake-plan-runner --flake "$flake_ref" --plan lib.ciPlans.x86_64-linux.publish \
  --manifest appliance-transfer/publish.json --timings appliance-transfer/publish.timings.json
maestro-ci-job-transfer export appliance appliance-transfer
