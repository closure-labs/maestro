#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "${MAESTRO_SYSTEM_ROOT:-$PWD}"

# Temporary comparison of ordinary flake outputs. No decision/evidence routing,
# upload, signing or acceptance: existing required validation stays in place.
printf '%s\n' 'Evaluate ordinary flake checks'
nix flake check --no-write-lock-file --no-build

printf '%s\n' 'Build the appliance, installer, pinned XO and operator tools'
nix build --no-write-lock-file --no-link \
  .#nixosConfigurations.maestro.config.system.build.toplevel \
  .#installer-iso \
  .#xen-orchestra-ce \
  .#maestro-menu \
  .#maestroctl \
  .#deploy-template

printf '%s\n' 'Run CLI, VM service/TLS/privilege, storage and file-restore checks'
nix build --no-write-lock-file --no-link \
  .#checks.x86_64-linux.maestroctl \
  .#checks.x86_64-linux.runtime-security \
  .#checks.x86_64-linux.xo-storage-fixtures \
  .#checks.x86_64-linux.xo-file-restore-fixtures
