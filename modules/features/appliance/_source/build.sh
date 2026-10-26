#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "${MAESTRO_SYSTEM_ROOT:-$PWD}"
mkdir -p appliance-transfer
flake-plan-runner --flake "path:$PWD" --plan lib.ciPlans.x86_64-linux.evidence \
  --manifest appliance-transfer/evidence.json --timings appliance-transfer/evidence.timings.json
flake-plan-runner --flake "path:$PWD" --plan lib.ciPlans.x86_64-linux.publish \
  --manifest appliance-transfer/publish.json --timings appliance-transfer/publish.timings.json
nix build --accept-flake-config --no-link .#distribution-inventory
maestro-ci-job-transfer export appliance appliance-transfer
