#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 077
[[ $(id -u) == 0 && $# == 1 ]] || {
  echo 'Usage (root console): maestro-enroll-bootstrap-key BASE64_PUBLIC_KEY' >&2; exit 2;
}
[[ $1 =~ ^[A-Za-z0-9+/=]+$ && ${#1} -le 1024 ]] || exit 2
key=$(printf '%s' "$1" | base64 --decode)
[[ $key != *$'\n'* && $key =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]][A-Za-z0-9_-]+)?$ ]] || exit 2
directory=${MAESTRO_BOOTSTRAP_DIR:-/run/maestro-bootstrap}
install -d -m 0755 -o root -g root "$directory"
temporary=$(mktemp "$directory/key.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
printf '%s\n' "$key" >"$temporary"
ssh-keygen -l -f "$temporary" >/dev/null
chmod 0644 "$temporary"
mv -T -- "$temporary" "$directory/authorized_keys"
echo 'Temporary Maestro build key enrolled.'
