#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
nix_cli=${1:?Missing hosted Nix executable}
max_jobs=${2:?Missing build job budget}
cores=${3:?Missing build core budget}

# Only the setup-installed store executable and positive numeric budgets may
# cross the step boundary. Validate every value before writing either file.
[[ $nix_cli =~ ^/nix/store/[a-z0-9]{32}-determinate-nix-[a-zA-Z0-9.+-]+/bin/nix$ ]]
[[ $max_jobs =~ ^[1-4]$ && $cores =~ ^[1-9][0-9]*$ ]]
# Determinate appends generated extra-substituters after nix.custom.conf. A
# process-level baseline wins over that order; explicitly accepted flake extras
# can still append their public caches and keys later. Never export inherited
# NIX_CONFIG: it may contain runtime credentials or unrelated overrides.
printf -v public_config 'substituters = https://cache.nixos.org/\nmax-jobs = %s\ncores = %s' "$max_jobs" "$cores"
{
  printf 'MAESTRO_CI_NIX_BIN=%s\n' "$nix_cli"
  printf 'SECRETSPEC_REASON=Maestro workflow runtime credentials\n'
  printf 'DEVENV_MAX_JOBS=%s\nDEVENV_CORES=%s\n' "$max_jobs" "$cores"
  printf 'NIX_CONFIG<<MAESTRO_CI_NIX_CONFIG_EOF\n%s\nMAESTRO_CI_NIX_CONFIG_EOF\n' "$public_config"
} >>"${GITHUB_ENV:?Missing GitHub environment file}"
printf '%s\n' "${nix_cli%/*}" >>"${GITHUB_PATH:?Missing GitHub path file}"
printf '%s\n' "$public_config"
