#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "${MAESTRO_SYSTEM_ROOT:-$PWD}"
[[ $(git rev-parse HEAD) == "${GITHUB_SHA:?}" ]]
flake_ref="git+file:$PWD?shallow=1&rev=$GITHUB_SHA"
export MAESTRO_NIX_EVENTS_DIR="$PWD/installer-transfer/nix-events"
maestro-ci-job-transfer restore appliance appliance-transfer
mkdir -p installer-transfer
flake-plan-runner --flake "$flake_ref" --plan lib.ciPlans.x86_64-linux.media \
  --manifest installer-transfer/media.json --timings installer-transfer/media.timings.json
maestro-ci-job-transfer export installer installer-transfer
