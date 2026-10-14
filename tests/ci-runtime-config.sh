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

mkdir "$temporary/bin"
printf '#!%s\nprintf "selected-runtime"\nprintf " <%%s>" "$@"\nprintf "\\n"\n' "$BASH" >"$temporary/bin/nix"
chmod +x "$temporary/bin/nix"
cp "$temporary/bin/nix" "$temporary/bin/nix-store"
sed "s|@fallback@|$temporary/bin|" "$root/nix/ci-nix.sh" >"$temporary/nix"
cp "$temporary/nix" "$temporary/nix-store"
result=$(GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/bin/nix" bash "$temporary/nix" config show cores)
[[ $result == 'selected-runtime <config> <show> <cores>' ]]
result=$(GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/bin/nix" bash "$temporary/nix-store" --query --references fixture)
[[ $result == 'selected-runtime <--query> <--references> <fixture>' ]]
result=$(GITHUB_ACTIONS=false bash "$temporary/nix" --version)
[[ $result == 'selected-runtime <--version>' ]]
if GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN='' bash "$temporary/nix"; then exit 1; fi
if GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/missing" bash "$temporary/nix"; then exit 1; fi
if GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN=relative bash "$temporary/nix"; then exit 1; fi
echo 'Hosted resource budgets and Nix runtime selection fixtures passed'
