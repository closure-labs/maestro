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
{
  printf 'MAESTRO_CI_NIX_BIN=%s\n' "$nix_cli"
  printf 'SECRETSPEC_REASON=Maestro workflow runtime credentials\n'
  printf 'DEVENV_MAX_JOBS=%s\nDEVENV_CORES=%s\n' "$max_jobs" "$cores"
} >>"${GITHUB_ENV:?Missing GitHub environment file}"
printf '%s\n' "${nix_cli%/*}" >>"${GITHUB_PATH:?Missing GitHub path file}"
