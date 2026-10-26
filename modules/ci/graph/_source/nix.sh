#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
nix_command=${0##*/}
case "$nix_command" in nix | nix-store | nix-env) ;; *) exit 1 ;; esac
if [[ ${GITHUB_ACTIONS:-false} == true ]]; then
  nix_bin=${MAESTRO_CI_NIX_BIN:-}
  if [[ $nix_bin != /* || ! -x $nix_bin ]]; then
    echo 'Hosted commands require the Determinate executable captured by setup-nix.' >&2
    exit 1
  fi
  nix_bin=${nix_bin%/*}/$nix_command
else
  nix_bin=@fallback@/$nix_command
fi
[[ -x $nix_bin ]] || { echo "Missing Nix companion executable: $nix_bin" >&2; exit 1; }
if [[ $nix_command == nix && -n ${MAESTRO_NIX_EVENTS_DIR:-} ]]; then
  mkdir -p "$MAESTRO_NIX_EVENTS_DIR"
  events=$(mktemp "$MAESTRO_NIX_EVENTS_DIR/nix.XXXXXX.jsonl")
  if "$nix_bin" --log-format internal-json "$@" 2> >(tee "$events" >&2); then
    status=0
  else
    status=$?
  fi
  wait
  printf '{"exitCode":%s}\n' "$status" >"$events.result.json"
  exit "$status"
fi
exec "$nix_bin" "$@"
