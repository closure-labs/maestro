#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=modules/features/operator/menu/_source/backend/lib.sh
. "$SCRIPT_DIR/lib.sh"

maestro_require_git_repo
maestro_cd_root

json_quote() {
  printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g')"
}

json_array() {
  # The caller passes the name of the array to serialize.
  # shellcheck disable=SC2178
  local -n items_ref="$1"
  local first=1
  local item

  printf '['
  for item in "${items_ref[@]}"; do
    if [ "$first" -eq 0 ]; then
      printf ', '
    fi
    json_quote "$item"
    first=0
  done
  printf ']'
}

json_bool() {
  case "${1:-}" in
    1|true|TRUE|yes|on)
      printf 'true'
      ;;
    *)
      printf 'false'
      ;;
  esac
}

load_apply_state() {
  last_apply_present=0
  last_apply_result=""
  last_apply_action=""
  last_apply_hostname=""
  last_apply_head=""
  last_apply_first_install=""
  last_apply_exit_code=""
  last_apply_timestamp=""

  apply_state_file="$(maestro_apply_state_file)"
  if [ ! -f "$apply_state_file" ]; then
    apply_state_file="$(maestro_legacy_apply_state_file)"
  fi
  if [ -f "$apply_state_file" ]; then
    # shellcheck source=/dev/null
    . "$apply_state_file"
    last_apply_present=1
  fi
}

load_rebuild_queue() {
  rebuild_queued=false
  rebuild_queued_at=""
  rebuild_queued_hostname=""

  rebuild_queue_file="$(maestro_rebuild_queue_file)"
  if [ -f "$rebuild_queue_file" ]; then
    rebuild_queued=true
    # shellcheck source=/dev/null
    . "$rebuild_queue_file"
    # These values are emitted after all state-loading functions run.
    # shellcheck disable=SC2034
    rebuild_queued_at="${scheduled_at:-}"
    # shellcheck disable=SC2034
    rebuild_queued_hostname="${target:-${hostname:-}}"
  fi
}

load_upstream_state() {
  current_branch="$(git -C "$MAESTRO_SYSTEM_ROOT" branch --show-current 2>/dev/null || printf '')"
  upstream_branch=""
  ahead_count=0
  behind_count=0

  if upstream_branch="$(git -C "$MAESTRO_SYSTEM_ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)"; then
    read -r ahead_count behind_count <<EOF
$(git -C "$MAESTRO_SYSTEM_ROOT" rev-list --left-right --count 'HEAD...@{upstream}' 2>/dev/null || printf '0 0')
EOF
  fi
}

load_memory_state() {
  local mem_total_kib
  local mem_available_kib

  mem_total_kib="$(sed -nE 's/^MemTotal:[[:space:]]*([0-9]+)[[:space:]]+kB$/\1/p' /proc/meminfo | head -n 1)"
  mem_available_kib="$(sed -nE 's/^MemAvailable:[[:space:]]*([0-9]+)[[:space:]]+kB$/\1/p' /proc/meminfo | head -n 1)"

  memory_total_bytes=0
  memory_used_bytes=0
  memory_used_percent=0

  if [ -n "$mem_total_kib" ] && [ -n "$mem_available_kib" ] && [ "$mem_total_kib" -gt 0 ]; then
    memory_total_bytes=$((mem_total_kib * 1024))
    memory_used_bytes=$(((mem_total_kib - mem_available_kib) * 1024))
    memory_used_percent=$((memory_used_bytes * 100 / memory_total_bytes))
  fi
}

load_storage_state() {
  storage_total_bytes=0
  storage_used_bytes=0
  storage_used_percent=0

  if read -r storage_total_bytes storage_used_bytes <<EOF
$(df -B1 -P / 2>/dev/null | awk 'NR == 2 { print $2, $3 }')
EOF
  then
    if [ "${storage_total_bytes:-0}" -gt 0 ]; then
      storage_used_percent=$((storage_used_bytes * 100 / storage_total_bytes))
    fi
  fi
}

load_network_state() {
  primary_ip="$(
    ip -o -4 route get 1.1.1.1 2>/dev/null \
      | awk '/src/ { for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }' \
      || true
  )"

  if [ -z "$primary_ip" ]; then
    primary_ip="$(hostname -I 2>/dev/null | awk '{ print $1 }' || true)"
  fi
}

lock_rev_for() {
  local node_name="$1"

  awk -v node_name="$node_name" '
    BEGIN {
      in_node = 0
      in_locked = 0
    }
    $0 ~ "^[[:space:]]*\"" node_name "\"[[:space:]]*:[[:space:]]*\\{" {
      in_node = 1
      next
    }
    in_node && $0 ~ /^[[:space:]]*"locked"[[:space:]]*:[[:space:]]*\{/ {
      in_locked = 1
      next
    }
    in_node && in_locked && $0 ~ /^[[:space:]]*"rev"[[:space:]]*:/ {
      line = $0
      sub(/^[[:space:]]*"rev"[[:space:]]*:[[:space:]]*"/, "", line)
      sub(/",?[[:space:]]*$/, "", line)
      print line
      exit
    }
    in_node && in_locked && $0 ~ /^[[:space:]]*}[,]?[[:space:]]*$/ {
      in_locked = 0
    }
  ' "$MAESTRO_SYSTEM_ROOT/flake.lock"
}

load_xoa_state() {
  local working_dir=""
  local package_path=""
  local package_name=""
  local locked_rev=""
  local scheme="http"

  xen_orchestra_version=""
  web_ui_url=""

  working_dir="$(systemctl show -p WorkingDirectory --value xo-server.service 2>/dev/null || true)"
  if [ -n "$working_dir" ]; then
    package_path="${working_dir%/libexec/xen-orchestra}"
    package_name="${package_path##*/}"
    xen_orchestra_version="$(printf '%s\n' "$package_name" | sed -nE 's/^[0-9a-z]{32}-xen-orchestra-ce-(.+)$/\1/p')"
  fi

  if [ -z "$xen_orchestra_version" ]; then
    locked_rev="$(lock_rev_for xen-orchestra-ce)"
    if [ -n "$locked_rev" ]; then
      xen_orchestra_version="rev $(printf '%.8s' "$locked_rev")"
    fi
  fi

  if maestro_tui_xo_tls_enabled /etc/xo-server/config.nixos-http.toml; then
    scheme="https"
  fi

  if [ -n "$primary_ip" ]; then
    web_ui_url="${scheme}://${primary_ip}"
  fi
}

mapfile -t ssh_keys < <(maestro_tui_ssh_keys)
mapfile -t system_packages < <(maestro_tui_extra_system_packages)
mapfile -t user_packages < <(maestro_tui_extra_user_packages)
mapfile -t services < <(maestro_tui_enabled_services)
load_apply_state
load_upstream_state
load_rebuild_queue
load_memory_state
load_storage_state
load_network_state
load_xoa_state

dirty_count="$(maestro_tui_dirty_count)"
current_head="$(git -C "$MAESTRO_SYSTEM_ROOT" rev-parse HEAD 2>/dev/null || printf '')"
rebuild_needed=true

if [ "$dirty_count" -eq 0 ] \
  && [ "$last_apply_present" -eq 1 ] \
  && [ "$last_apply_result" = "success" ] \
  && [ "$last_apply_action" = "switch" ] \
  && [ "$last_apply_head" = "$current_head" ]
then
  rebuild_needed=false
fi

if [ "${1:-}" = "--json" ]; then
  printf '{\n'
  printf '  "hostname": %s,\n' "$(json_quote "$(maestro_tui_hostname)")"
  printf '  "username": %s,\n' "$(json_quote "$(maestro_tui_username)")"
  printf '  "timezone": %s,\n' "$(json_quote "$(maestro_tui_timezone)")"
  printf '  "extras": %s,\n' "$(maestro_tui_enable_extras)"
  printf '  "developmentMode": %s,\n' "$(maestro_tui_development_mode)"
  printf '  "sshKeys": '
  json_array ssh_keys
  printf ',\n'
  printf '  "systemPackages": '
  json_array system_packages
  printf ',\n'
  printf '  "userPackages": '
  json_array user_packages
  printf ',\n'
  printf '  "services": '
  json_array services
  printf ',\n'
  printf '  "dirtyCount": %s,\n' "$dirty_count"
  printf '  "head": %s,\n' "$(json_quote "$current_head")"
  printf '  "branch": %s,\n' "$(json_quote "$current_branch")"
  if [ -n "$upstream_branch" ]; then
    printf '  "upstream": %s,\n' "$(json_quote "$upstream_branch")"
  else
    printf '  "upstream": null,\n'
  fi
  printf '  "ahead": %s,\n' "$ahead_count"
  printf '  "behind": %s,\n' "$behind_count"
  printf '  "memoryTotalBytes": %s,\n' "$memory_total_bytes"
  printf '  "memoryUsedBytes": %s,\n' "$memory_used_bytes"
  printf '  "memoryUsedPercent": %s,\n' "$memory_used_percent"
  printf '  "storageTotalBytes": %s,\n' "$storage_total_bytes"
  printf '  "storageUsedBytes": %s,\n' "$storage_used_bytes"
  printf '  "storageUsedPercent": %s,\n' "$storage_used_percent"
  if [ -n "$primary_ip" ]; then
    printf '  "primaryIp": %s,\n' "$(json_quote "$primary_ip")"
  else
    printf '  "primaryIp": null,\n'
  fi
  if [ -n "$xen_orchestra_version" ]; then
    printf '  "xenOrchestraVersion": %s,\n' "$(json_quote "$xen_orchestra_version")"
  else
    printf '  "xenOrchestraVersion": null,\n'
  fi
  if [ -n "$web_ui_url" ]; then
    printf '  "webUiUrl": %s,\n' "$(json_quote "$web_ui_url")"
  else
    printf '  "webUiUrl": null,\n'
  fi
  printf '  "rebuildQueued": %s,\n' "$rebuild_queued"
  printf '  "rebuildNeeded": %s,\n' "$rebuild_needed"
  if [ "$last_apply_present" -eq 1 ]; then
    printf '  "lastApply": {\n'
    printf '    "result": %s,\n' "$(json_quote "$last_apply_result")"
    printf '    "action": %s,\n' "$(json_quote "$last_apply_action")"
    printf '    "hostname": %s,\n' "$(json_quote "$last_apply_hostname")"
    printf '    "head": %s,\n' "$(json_quote "$last_apply_head")"
    printf '    "firstInstall": %s,\n' "$(json_bool "${last_apply_first_install:-false}")"
    printf '    "exitCode": %s,\n' "${last_apply_exit_code:-0}"
    printf '    "timestamp": %s\n' "$(json_quote "$last_apply_timestamp")"
    printf '  }\n'
  else
    printf '  "lastApply": null\n'
  fi
  printf '}\n'
  exit 0
fi

printf 'hostname=%s\n' "$(maestro_tui_hostname)"
printf 'username=%s\n' "$(maestro_tui_username)"
printf 'timezone=%s\n' "$(maestro_tui_timezone)"
printf 'extras=%s\n' "$(maestro_tui_enable_extras)"
printf 'development_mode=%s\n' "$(maestro_tui_development_mode)"
printf 'ssh_key_count=%s\n' "${#ssh_keys[@]}"
printf 'system_package_count=%s\n' "${#system_packages[@]}"
printf 'user_package_count=%s\n' "${#user_packages[@]}"
printf 'service_count=%s\n' "${#services[@]}"
printf 'dirty_count=%s\n' "$dirty_count"
printf 'branch=%s\n' "$current_branch"
printf 'upstream=%s\n' "$upstream_branch"
printf 'ahead=%s\n' "$ahead_count"
printf 'behind=%s\n' "$behind_count"
printf 'memory_total_bytes=%s\n' "$memory_total_bytes"
printf 'memory_used_bytes=%s\n' "$memory_used_bytes"
printf 'memory_used_percent=%s\n' "$memory_used_percent"
printf 'storage_total_bytes=%s\n' "$storage_total_bytes"
printf 'storage_used_bytes=%s\n' "$storage_used_bytes"
printf 'storage_used_percent=%s\n' "$storage_used_percent"
printf 'primary_ip=%s\n' "$primary_ip"
printf 'xen_orchestra_version=%s\n' "$xen_orchestra_version"
printf 'web_ui_url=%s\n' "$web_ui_url"
printf 'rebuild_queued=%s\n' "$rebuild_queued"
printf 'rebuild_needed=%s\n' "$rebuild_needed"
