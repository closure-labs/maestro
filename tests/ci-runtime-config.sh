#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

for row in '2 7168 1 2' '4 16384 2 2' '8 16384 2 2' '8 32768 4 2' '8 8192 1 3' '1 1024 1 1'; do
  read -r cpus memory jobs cores <<<"$row"
  result=$(bash "$root/.github/actions/setup-nix/resources.sh" "$cpus" "$memory")
  [[ $result == "max-jobs = $jobs"$'\n'"cores = $cores" ]]
  ((jobs * cores <= cpus))
done
if bash "$root/.github/actions/setup-nix/resources.sh" 0 8192; then exit 1; fi

export GITHUB_ENV="$temporary/environment" GITHUB_PATH="$temporary/path"
hosted_nix=/nix/store/0123456789abcdefghijklmnopqrstuv-determinate-nix-3.21.9/bin/nix
public_config=$(NIX_CONFIG='access-tokens = fixture-invalid-ambient-value' bash "$root/.github/actions/setup-nix/export-runtime.sh" "$hosted_nix" 1 3)
expected_config=$'substituters = https://cache.nixos.org/\nmax-jobs = 1\ncores = 3'
[[ $public_config == "$expected_config" ]]
expected_env=$(printf 'MAESTRO_CI_NIX_BIN=%s\nSECRETSPEC_REASON=Maestro workflow runtime credentials\nDEVENV_MAX_JOBS=1\nDEVENV_CORES=3' "$hosted_nix")
expected_env+=$'\nNIX_CONFIG<<MAESTRO_CI_NIX_CONFIG_EOF\n'
expected_env+="$expected_config"$'\nMAESTRO_CI_NIX_CONFIG_EOF'
[[ $(cat "$GITHUB_ENV") == "$expected_env" ]]
[[ $(cat "$GITHUB_PATH") == "${hosted_nix%/*}" ]]
for invalid in "$hosted_nix"$'\nLD_PRELOAD=/tmp/evil' /tmp/nix /nix/store/invalid/bin/nix; do
  if bash "$root/.github/actions/setup-nix/export-runtime.sh" "$invalid" 1 3; then exit 1; fi
done
for invalid in 0 5 $'1\nLD_PRELOAD=/tmp/evil'; do
  if bash "$root/.github/actions/setup-nix/export-runtime.sh" "$hosted_nix" "$invalid" 3; then exit 1; fi
done
for invalid in 0 -1 $'3\nLD_PRELOAD=/tmp/evil'; do
  if bash "$root/.github/actions/setup-nix/export-runtime.sh" "$hosted_nix" 1 "$invalid"; then exit 1; fi
done
[[ $(cat "$GITHUB_ENV") == "$expected_env" ]]
[[ $(cat "$GITHUB_PATH") == "${hosted_nix%/*}" ]]

# Reproduce the real generated include order with the native Nix parser.
# A custom-file setting alone loses to later extra-substituters; the current
# process and the next Actions step must use the same static public baseline.
mkdir "$temporary/config"
cat >"$temporary/config/nix.conf" <<'CONFIG'
experimental-features = nix-command flakes
!include nix.custom.conf
extra-substituters = https://cache.flakehub.com/ https://edge.cache.flakehub.com/
max-jobs = 99
cores = 99
CONFIG
printf '%s\n' "$expected_config" >"$temporary/config/nix.custom.conf"
native_nix=$(command -v nix)
config_show() {
  NIX_CONF_DIR="$temporary/config" NIX_USER_CONF_FILES=/dev/null "$native_nix" "$@"
}
old_substituters=$(NIX_CONFIG='' config_show config show substituters)
[[ $old_substituters == *https://cache.flakehub.com/* && $old_substituters == *https://edge.cache.flakehub.com/* ]]
[[ $(NIX_CONFIG="$public_config" config_show config show substituters) == https://cache.nixos.org/ ]]
[[ $(NIX_CONFIG="$public_config" config_show config show max-jobs) == 1 ]]
[[ $(NIX_CONFIG="$public_config" config_show config show cores) == 3 ]]
next_step_config=$(sed -n '/^NIX_CONFIG<<MAESTRO_CI_NIX_CONFIG_EOF$/,/^MAESTRO_CI_NIX_CONFIG_EOF$/p' "$GITHUB_ENV" | sed '1d;$d')
[[ $next_step_config == "$public_config" ]]
[[ $(NIX_CONFIG="$next_step_config" config_show config show substituters) == https://cache.nixos.org/ ]]
# Explicit per-command additions, like accepted flake nixConfig extras, remain
# additive rather than being removed by the process-level baseline.
project_cache=https://maestro.cachix.org
project_key='maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0='
[[ $(NIX_CONFIG="$public_config" config_show --option extra-substituters "$project_cache" config show substituters) == "https://cache.nixos.org/ $project_cache" ]]
[[ $(NIX_CONFIG="$public_config" config_show --option extra-trusted-public-keys "$project_key" config show trusted-public-keys) == *"$project_key"* ]]

mkdir "$temporary/bin"
printf '#!%s\nprintf "selected-runtime"\nprintf " <%%s>" "$@"\nprintf "\\n"\n' "$BASH" >"$temporary/bin/nix"
chmod +x "$temporary/bin/nix"
cp "$temporary/bin/nix" "$temporary/bin/nix-store"
cp "$temporary/bin/nix" "$temporary/bin/nix-env"
sed "s|@fallback@|$temporary/bin|" "$root/nix/ci-nix.sh" >"$temporary/nix"
cp "$temporary/nix" "$temporary/nix-store"
cp "$temporary/nix" "$temporary/nix-env"
result=$(GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/bin/nix" bash "$temporary/nix" config show cores)
[[ $result == 'selected-runtime <config> <show> <cores>' ]]
result=$(GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/bin/nix" bash "$temporary/nix-store" --query --references fixture)
[[ $result == 'selected-runtime <--query> <--references> <fixture>' ]]
result=$(GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/bin/nix" bash "$temporary/nix-env" -qa --meta --json -f fixture)
[[ $result == 'selected-runtime <-qa> <--meta> <--json> <-f> <fixture>' ]]
rm "$temporary/bin/nix-env"
if GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/bin/nix" bash "$temporary/nix-env" -qa; then exit 1; fi
result=$(GITHUB_ACTIONS=false bash "$temporary/nix" --version)
[[ $result == 'selected-runtime <--version>' ]]
if GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN='' bash "$temporary/nix"; then exit 1; fi
if GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/missing" bash "$temporary/nix"; then exit 1; fi
if GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN=relative bash "$temporary/nix"; then exit 1; fi
echo 'Hosted resource budgets, public cache precedence and Nix runtime selection fixtures passed'
