#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${MAESTRO_XO_STORAGE_HELPER:?MAESTRO_XO_STORAGE_HELPER must be set}"
: "${MAESTRO_XO_SUDO:?MAESTRO_XO_SUDO must be set}"

sudo_options=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -n|-E|-H) sudo_options+=("$1"); shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done

if [ "${1:-}" = mount ]; then
  shift
  fstype="" options=""
  args=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -t|--types)
        fstype="$2"
        args+=("$1" "$2")
        shift 2
        ;;
      -o|--options)
        options="$2"
        shift 2
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done
  if [ "$fstype" = cifs ] && [ -n "${USER:-}" ] && [ -n "${PASSWD:-}" ]; then
    if [ -n "$options" ]; then
      printf '%s\n%s\n' "$USER" "$PASSWD" \
        | "$MAESTRO_XO_SUDO" "${sudo_options[@]}" "$MAESTRO_XO_STORAGE_HELPER" mount-cifs-with-credentials -o "$options" "${args[@]}"
    else
      printf '%s\n%s\n' "$USER" "$PASSWD" \
        | "$MAESTRO_XO_SUDO" "${sudo_options[@]}" "$MAESTRO_XO_STORAGE_HELPER" mount-cifs-with-credentials "${args[@]}"
    fi
    exit $?
  fi
  if [ -n "$options" ]; then
    exec "$MAESTRO_XO_SUDO" "${sudo_options[@]}" "$MAESTRO_XO_STORAGE_HELPER" mount -o "$options" "${args[@]}"
  fi
  exec "$MAESTRO_XO_SUDO" "${sudo_options[@]}" "$MAESTRO_XO_STORAGE_HELPER" mount "${args[@]}"
fi
exec "$MAESTRO_XO_SUDO" "${sudo_options[@]}" "$MAESTRO_XO_STORAGE_HELPER" "$@"
