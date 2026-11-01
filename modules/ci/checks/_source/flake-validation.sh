#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "${MAESTRO_SYSTEM_ROOT:-$PWD}"

# Temporary comparison of ordinary flake outputs. No decision/evidence routing,
# upload, signing or acceptance: existing required validation stays in place.
# Match legacy's declared public cache inputs without accepting arbitrary flake
# settings or adding URLs/keys. Values come from modules/flake/caches.nix at
# package construction, not workflow inputs or credentials.
export NIX_CONFIG="${NIX_CONFIG:-}
extra-substituters = ${MAESTRO_FLAKE_CACHE_URLS:?}
extra-trusted-public-keys = ${MAESTRO_FLAKE_CACHE_KEYS:?}"

printf '%s\n' 'Realize all ordinary flake checks (including every legacy obligation)' >&2
nix flake check --no-write-lock-file --print-build-logs

printf '%s\n' 'Build the appliance, installer, pinned XO and operator tools' >&2
nix build --no-write-lock-file --no-link --print-build-logs \
  .#nixosConfigurations.maestro.config.system.build.toplevel \
  .#installer-iso \
  .#xen-orchestra-ce \
  .#maestro-menu \
  .#maestroctl \
  .#deploy-template

printf '%s\n' 'Ordinary flake validation completed' >&2
