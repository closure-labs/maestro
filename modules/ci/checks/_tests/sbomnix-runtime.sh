#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_SBOMNIX:?MAESTRO_SBOMNIX must identify the packaged sbomnix executable}"
temporary=$(mktemp -d)
cleanup() {
  status=$?
  if ((status != 0)); then
    for log in "$temporary"/*.log; do
      [[ ! -f "$log" ]] || cat "$log" >&2
    done
  fi
  rm -rf -- "$temporary"
  exit "$status"
}
trap cleanup EXIT
mkdir -p "$temporary/bin" "$temporary/cache"
export TMPDIR="$temporary/cache"
export GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/bin/nix"
export RUNTIME_TRACE="$temporary/runtime.trace"
printf '#!%s\n' "$BASH" >"$MAESTRO_CI_NIX_BIN"
cat >>"$MAESTRO_CI_NIX_BIN" <<'RUNTIME'
set -euo pipefail
printf '%s\n' "${0##*/}" "$@" >>"$RUNTIME_TRACE"
if [[ ${0##*/} == nix && ${1:-} == flake && ${2:-} == metadata && -n ${RUNTIME_METADATA_PATH:-} ]]; then
  case ${RUNTIME_METADATA_INVALID:-false} in
    empty) printf '{"path":"","description":"A collection of packages for the Nix package manager"}\n'; exit 0 ;;
    malformed) printf '[]\n'; exit 0 ;;
  esac
  case "$*" in
    *'--option lazy-trees false'*)
      if [[ ${RUNTIME_METADATA_INVALID:-false} == true ]]; then
        printf '{"description":"A collection of packages for the Nix package manager"}\n'
      else
        jq -n --arg path "$RUNTIME_METADATA_PATH" '{path: $path, description: "A collection of packages for the Nix package manager"}'
      fi
      ;;
    *) printf '{"description":"A collection of packages for the Nix package manager"}\n' ;;
  esac
  exit 0
fi
exit 77
RUNTIME
chmod +x "$MAESTRO_CI_NIX_BIN"
flake='path:/fixture#nixosConfigurations.maestro.config.system.build.toplevel'
if "$MAESTRO_SBOMNIX" "$flake" >"$temporary/captured.log" 2>&1; then
  echo 'sbomnix ignored a captured runtime failure' >&2
  exit 1
fi
[[ -s "$RUNTIME_TRACE" ]]
grep -Fx -- nix "$RUNTIME_TRACE" >/dev/null
grep -Fx -- eval "$RUNTIME_TRACE" >/dev/null
grep -Fx -- --raw "$RUNTIME_TRACE" >/dev/null
grep -Fx -- "$flake" "$RUNTIME_TRACE" >/dev/null

# Exercise the actual metadata scanner, with no preexisting metadata cache.
mkdir "$temporary/fixture-nixpkgs"
export RUNTIME_METADATA_PATH="$temporary/fixture-nixpkgs"
cp "$MAESTRO_CI_NIX_BIN" "$temporary/bin/nix-env"
rm "$RUNTIME_TRACE"
if "${MAESTRO_SBOMNIX%/*}/nixmeta" --flakeref "$temporary/fixture-nixpkgs" --out "$temporary/meta.csv" >"$temporary/metadata.log" 2>&1; then
  echo 'nixmeta ignored a captured companion failure' >&2
  exit 1
fi
grep -Fx -- nix-env "$RUNTIME_TRACE" >/dev/null
for argument in -qa --meta --json -f "$temporary/fixture-nixpkgs" --option lazy-trees false; do
  grep -Fx -- "$argument" "$RUNTIME_TRACE" >/dev/null
done
rm "$temporary/bin/nix-env"
if "${MAESTRO_SBOMNIX%/*}/nixmeta" --flakeref "$temporary/fixture-nixpkgs" --out "$temporary/meta.csv" >"$temporary/companion.log" 2>&1; then
  echo 'nixmeta accepted a missing captured companion' >&2
  exit 1
fi
grep -F 'Missing Nix companion executable:' "$temporary/companion.log" >/dev/null
if RUNTIME_METADATA_INVALID=true "${MAESTRO_SBOMNIX%/*}/nixmeta" --flakeref "$temporary/fixture-nixpkgs" --out "$temporary/meta.csv" >"$temporary/invalid.log" 2>&1; then
  echo 'nixmeta accepted metadata without a materialized source path' >&2
  exit 1
fi
grep -F 'Materialized flake metadata is missing its source path' "$temporary/invalid.log" >/dev/null
if RUNTIME_METADATA_INVALID=empty "${MAESTRO_SBOMNIX%/*}/nixmeta" --flakeref "$temporary/fixture-nixpkgs" --out "$temporary/meta.csv" >"$temporary/empty.log" 2>&1; then
  echo 'nixmeta accepted an empty metadata source path' >&2
  exit 1
fi
grep -F 'Materialized flake metadata is missing its source path' "$temporary/empty.log" >/dev/null
if RUNTIME_METADATA_INVALID=malformed "${MAESTRO_SBOMNIX%/*}/nixmeta" --flakeref "$temporary/fixture-nixpkgs" --out "$temporary/meta.csv" >"$temporary/malformed.log" 2>&1; then
  echo 'nixmeta accepted non-object flake metadata' >&2
  exit 1
fi
grep -F 'Malformed flake metadata' "$temporary/malformed.log" >/dev/null
touch "$temporary/not-a-directory"
for invalid_path in "$temporary/missing-directory" "$temporary/not-a-directory" relative-metadata; do
  if RUNTIME_METADATA_PATH="$invalid_path" "${MAESTRO_SBOMNIX%/*}/nixmeta" --flakeref "$temporary/fixture-nixpkgs" --out "$temporary/meta.csv" >"$temporary/path.log" 2>&1; then
    echo 'nixmeta accepted an invalid metadata source directory' >&2
    exit 1
  fi
  grep -F 'Flake metadata source path is not an existing absolute directory' "$temporary/path.log" >/dev/null
done

rm "$RUNTIME_TRACE"
unset RUNTIME_METADATA_PATH
unset MAESTRO_CI_NIX_BIN
if "$MAESTRO_SBOMNIX" "$flake" >"$temporary/missing.log" 2>&1; then
  echo 'sbomnix accepted a missing captured runtime' >&2
  exit 1
fi
grep -F 'Hosted commands require the Determinate executable captured by setup-nix.' "$temporary/missing.log" >/dev/null
[[ ! -e "$RUNTIME_TRACE" ]]
echo 'Packaged sbomnix captured-runtime and fail-closed fixtures passed'
