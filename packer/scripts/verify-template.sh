#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly XO_READINESS_GRACE_SECONDS="${XO_READINESS_GRACE_SECONDS:-0}"

[[ "$XO_READINESS_GRACE_SECONDS" =~ ^[0-9]+$ ]] || {
  printf 'XO readiness grace period must be a non-negative integer.\n' >&2
  exit 2
}

[[ "$(id -u)" -eq 0 ]] || {
  printf 'Maestro template verification must run as root.\n' >&2
  exit 1
}

report_error() {
  status=$?
  printf 'Maestro template verification failed at line %s (status %s).\n' \
    "${BASH_LINENO[0]}" "$status" >&2
  exit "$status"
}
trap report_error ERR

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

cloud_status=0
cloud-init status --wait --long || cloud_status=$?
case "$cloud_status" in
  0)
    ;;
  2)
    [[ "$(cloud-id 2>/dev/null | tr '[:upper:]' '[:lower:]')" == none ]]
    ;;
  *)
    exit "$cloud_status"
    ;;
esac

active_units=(
  cloud-config.service
  redis-xo.service
  sshd.service
  xen-guest-agent.service
  xo-server.service
)

deadline=$((SECONDS + 900))
while :; do
  inactive_units=()
  for unit in "${active_units[@]}"; do
    systemctl is-active --quiet "$unit" || inactive_units+=("$unit")
  done
  [[ "${#inactive_units[@]}" -eq 0 ]] && break
  if ((SECONDS >= deadline)); then
    printf 'Timed out waiting for services: %s\n' "${inactive_units[*]}" >&2
    systemctl --no-pager --full status "${inactive_units[@]}" || true
    exit 1
  fi
  sleep 2
done

systemctl is-enabled --quiet \
  cloud-init-local.service \
  redis-xo.service \
  sshd.service \
  xen-guest-agent.service \
  xo-server.service

test -d /home/maestro/maestro/.git
test -s /home/maestro/maestro/host/hardware-configuration.nix
grep -Fq 'networking.hostName = "maestro";' \
  /home/maestro/maestro/host/settings.nix
grep -Fq 'authorizedKeys.keys = lib.mkAfter' \
  /home/maestro/maestro/host/packer.nix

sshd -t
assert_sshd_directive /etc/ssh/sshd_config PermitRootLogin no
assert_sshd_directive /etc/ssh/sshd_config PasswordAuthentication no
assert_sshd_directive /etc/ssh/sshd_config AllowUsers maestro

test "$(redis-cli -s /run/redis-xo/redis.sock --raw PING)" = PONG

# systemd considers xo-server active as soon as the Node process starts, while
# its plugins and HTTPS listener can need additional time on the first boot.
if ((XO_READINESS_GRACE_SECONDS > 0)); then
  printf 'Waiting %s seconds before checking Xen Orchestra HTTPS readiness.\n' \
    "$XO_READINESS_GRACE_SECONDS"
  sleep "$XO_READINESS_GRACE_SECONDS"
fi
while ! curl \
  --connect-timeout 2 \
  --fail \
  --insecure \
  --max-time 5 \
  --output /dev/null \
  --silent \
  https://127.0.0.1/; do
  if ! systemctl is-active --quiet xo-server.service; then
    systemctl --no-pager --full status xo-server.service || true
    journalctl --no-pager -u xo-server.service -n 100 || true
    exit 1
  fi
  if ((SECONDS >= deadline)); then
    printf 'Timed out waiting for the Xen Orchestra HTTPS endpoint.\n' >&2
    systemctl --no-pager --full status xo-server.service || true
    journalctl --no-pager -u xo-server.service -n 100 || true
    ss -lnt || true
    exit 1
  fi
  sleep 2
done
ss -lnt | grep -Eq '[:.]443[[:space:]]'

printf 'Maestro template verification passed.\n'
