#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

assert_sshd_directive() {
  local config=$1 directive=$2 expected=$3 actual
  actual=$(awk -v directive="$directive" '
    tolower($1) == "match" { exit }
    tolower($1) == tolower(directive) {
      $1 = ""
      sub(/^[[:space:]]+/, "")
      print
      exit
    }
  ' "$config")
  if [[ "$actual" != "$expected" ]]; then
    printf 'Expected global sshd directive %s=%s, got %s.\n' \
      "$directive" "$expected" "${actual:-<unset>}" >&2
    return 1
  fi
}

[[ "$(id -u)" -eq 0 ]] || {
  printf 'Maestro template sealing must run as root.\n' >&2
  exit 1
}

repo=/home/maestro/maestro
test -d "$repo/.git"
export MAESTRO_SYSTEM_ROOT=$repo
# shellcheck source=scripts/lib/common.sh
source "$repo/scripts/lib/common.sh"

bootstrap_key=$(sed -nE 's/.*lib.mkAfter \[ "(ssh-ed25519 [A-Za-z0-9+/=]+)" \].*/\1/p' "$repo/host/packer.nix")
[[ -n $bootstrap_key ]] || { echo 'Missing temporary build key before sealing.' >&2; exit 1; }

canonical_module="$(mktemp "$repo/host/.packer-canonical.XXXXXX")"
cleanup() {
  rm -f -- "${canonical_module:-}"
}
trap cleanup EXIT HUP INT TERM

git -C "$repo" show HEAD:host/packer.nix >"$canonical_module"
chmod 0644 "$canonical_module"
mv -f "$canonical_module" "$repo/host/packer.nix"
canonical_module=

nixos-rebuild --accept-flake-config switch --flake "path:$repo#maestro"

sshd -t -f /etc/ssh/sshd_config
assert_sshd_directive /etc/ssh/sshd_config PasswordAuthentication no
assert_sshd_directive /etc/ssh/sshd_config PermitRootLogin no
# Neither the bootstrap authorization nor enrollment files may survive sealing.
rm -rf -- /run/maestro-bootstrap
if grep -RFq -- "$bootstrap_key" /etc/ssh/authorized_keys.d; then
  echo 'Bootstrap key survived sealing.' >&2
  exit 1
fi
passwd --lock maestro
case "$(getent shadow maestro | cut -d: -f2)" in
  '!'*|'*'*) ;;
  *)
    printf 'The maestro password was not locked while sealing.\n' >&2
    exit 1
    ;;
esac

git -C "$repo" add \
  host/hardware-configuration.nix \
  host/settings.nix
if ! git -C "$repo" diff --cached --quiet; then
  git -C "$repo" \
    -c user.name="Maestro Packer" \
    -c user.email="packer@maestro" \
    commit -m "Configure generated Maestro template"
fi
test -z "$(git -C "$repo" status --short)"
current_head="$(git -C "$repo" rev-parse HEAD)"
maestro_write_apply_state success switch "$current_head" 1 0
chown -R maestro:users "$repo"

nh clean all

cloud-init clean --logs --machine-id --seed
rm -f -- /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
rm -f -- /var/lib/systemd/random-seed

if [[ -s /etc/machine-id ]]; then
  grep -Fqx uninitialized /etc/machine-id
fi
test -z "$(find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key*' -print -quit)"

sync
printf 'Maestro template sealed for NoCloud cloning.\n'
