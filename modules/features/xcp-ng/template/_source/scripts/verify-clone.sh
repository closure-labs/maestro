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
  printf 'Maestro clone verification must run as root.\n' >&2
  exit 1
}

cloud-init status --wait --long
test "$(cloud-id 2>/dev/null | tr '[:upper:]' '[:lower:]')" = nocloud

machine_id=$(</etc/machine-id)
[[ "$machine_id" =~ ^[0-9a-f]{32}$ ]]
for key_type in ed25519 rsa; do
  test -s "/etc/ssh/ssh_host_${key_type}_key"
  ssh-keygen -l -f "/etc/ssh/ssh_host_${key_type}_key.pub" >/dev/null
done

sshd -t -f /etc/ssh/sshd_config
assert_sshd_directive /etc/ssh/sshd_config PasswordAuthentication no
assert_sshd_directive /etc/ssh/sshd_config PermitRootLogin no
test -s /home/maestro/.ssh/authorized_keys

apply_state=/var/lib/maestro/apply-state.env
test -r "$apply_state"
grep -Fqx last_apply_result=success "$apply_state"
grep -Fqx last_apply_action=switch "$apply_state"
grep -Fqx \
  "last_apply_head=$(git -C /home/maestro/maestro rev-parse HEAD)" \
  "$apply_state"

systemctl is-active --quiet \
  redis-xo.service \
  sshd.service \
  xen-guest-agent.service \
  xo-server.service
test "$(redis-cli -s /run/redis-xo/redis.sock --raw PING)" = PONG
curl --fail --silent --show-error --insecure https://127.0.0.1/ >/dev/null

printf 'Maestro NoCloud clone verification passed.\n'
