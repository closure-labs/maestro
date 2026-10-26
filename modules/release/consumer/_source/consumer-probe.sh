#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
exec python3 "$MAESTRO_CONSUMER_PROBE_SOURCE" --config "${MAESTRO_SYSTEM_ROOT:-.}/modules/ci/authority/_source/decision-policy.json" \
  --cache https://maestro.cachix.org --key 'maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0=' \
  --proposal-hash "${CANDIDATE_PROPOSAL_HASH:-}"
