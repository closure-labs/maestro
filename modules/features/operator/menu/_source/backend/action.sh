#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=modules/features/operator/menu/_source/backend/lib.sh
. "$SCRIPT_DIR/lib.sh"

maestro_require_git_repo
maestro_cd_root

usage() {
  cat <<'EOF'
Usage: action.sh <command> [value]

Commands:
  set-ssh-key VALUE
  add-ssh-key VALUE
  remove-ssh-key VALUE
  toggle-extras
  set-development-mode true|false
  toggle-development-mode
  add-system-package VALUE
  add-user-package VALUE
  add-service VALUE
  update-nixpkgs
  update-home-manager
  update-determinate
  update-xoa
  update-all
  cleanup-unmanaged-users
EOF
}

load_state() {
  username_value="$(maestro_tui_username)"
  extras_value="$(maestro_tui_enable_extras)"
  development_mode_value="$(maestro_tui_development_mode)"

  mapfile -t ssh_keys_value < <(maestro_tui_ssh_keys)
  # These arrays are passed to the override writer by name.
  # shellcheck disable=SC2034
  mapfile -t system_packages_value < <(maestro_tui_extra_system_packages)
  # shellcheck disable=SC2034
  mapfile -t user_packages_value < <(maestro_tui_extra_user_packages)
  # shellcheck disable=SC2034
  mapfile -t services_value < <(maestro_tui_enabled_services)
}

commit_lock_if_changed() {
  local message="$1"

  if [ -z "$(git -C "$MAESTRO_SYSTEM_ROOT" status --short -- flake.lock)" ]; then
    echo "No flake.lock changes were produced."
    return 1
  fi

  maestro_tui_commit_paths "$message" flake.lock
}

prompt_yes_no() {
  local prompt="$1"
  local reply=""

  if [ ! -t 0 ]; then
    return 1
  fi

  read -r -p "$prompt [y/N]: " reply
  case "$reply" in
    y|Y|yes|YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

prompt_rebuild_policy() {
  if prompt_yes_no "Rebuild now"; then
    "$MAESTRO_SYSTEM_ROOT/modules/features/operator/cli/_source/maestroctl.sh" apply
    return 0
  fi

  if prompt_yes_no "Queue rebuild for next boot"; then
    maestro_schedule_rebuild_on_boot "$MAESTRO_SYSTEM_ROOT"
    echo "Queued a rebuild for the next boot."
    return 0
  fi

  echo "Skipped rebuild."
}

update_input_and_prompt() {
  local commit_message="$1"
  shift

  "$@"

  if commit_lock_if_changed "$commit_message"; then
    prompt_rebuild_policy
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

cleanup_unmanaged_users() {
  local managed_user="$1"
  local username=""
  local home_dir=""
  local -a targets=()
  local -a homes=()
  local entry=""
  local dir=""
  local total_targets=0
  local current_target=0
  local removed_users=0
  local removed_orphans=0

  echo "[1/4] Scanning for unmanaged users under /home..."

  while IFS=: read -r username _ _ _ _ home_dir _; do
    [ -n "$username" ] || continue
    [ "$username" = "$managed_user" ] && continue
    case "$home_dir" in
      /home/*)
        targets+=("$username")
        homes+=("$home_dir")
        ;;
    esac
  done < <(getent passwd)

  total_targets="${#targets[@]}"

  if [ "${#targets[@]}" -eq 0 ]; then
    echo "No unmanaged users under /home were found."
  else
    echo "[2/4] Removing unmanaged users:"
    printf '  - %s\n' "${targets[@]}"

    local i
    for i in "${!targets[@]}"; do
      username="${targets[$i]}"
      home_dir="${homes[$i]}"
      current_target=$((i + 1))

      printf '[2/4] [%d/%d] Removing user %s and home %s\n' \
        "$current_target" "$total_targets" "$username" "$home_dir"

      loginctl terminate-user "$username" >/dev/null 2>&1 || true
      loginctl disable-linger "$username" >/dev/null 2>&1 || true
      pkill -KILL -u "$username" >/dev/null 2>&1 || true

      if id "$username" >/dev/null 2>&1; then
        userdel --remove "$username"
      fi

      if [ -d "$home_dir" ]; then
        rm -rf --one-file-system "$home_dir"
      fi

      removed_users=$((removed_users + 1))
    done
  fi

  echo "[3/4] Removing orphan home directories..."
  for dir in /home/*; do
    [ -d "$dir" ] || continue
    [ "$dir" = "/home/$managed_user" ] && continue

    entry="$(getent passwd "$(basename "$dir")" || true)"
    if [ -z "$entry" ]; then
      echo "Removing orphan home directory: $dir"
      rm -rf --one-file-system "$dir"
      removed_orphans=$((removed_orphans + 1))
    fi
  done

  echo "[4/4] Cleanup complete."
  printf 'Removed %d unmanaged users and %d orphan home directories.\n' \
    "$removed_users" "$removed_orphans"
}

if [ $# -lt 1 ]; then
  usage >&2
  exit 1
fi

command_name="$1"
shift

load_state
host_menu_relpath="$(maestro_host_relpath)/menu.nix"

case "$command_name" in
  set-username)
    echo "The Maestro operator is fixed to maestro." >&2
    exit 1
    ;;
  set-ssh-key)
    [ $# -eq 1 ] || { usage >&2; exit 1; }
    maestro_tui_validate_ssh_key "$1"
    ssh_keys_value=("$1")
    maestro_tui_write_menu \
      "$extras_value" \
      "$development_mode_value" \
      ssh_keys_value \
      system_packages_value \
      user_packages_value \
      services_value
    maestro_tui_commit_paths "Set SSH key from maestro-menu" "$host_menu_relpath"
    ;;
  add-ssh-key)
    [ $# -eq 1 ] || { usage >&2; exit 1; }
    maestro_tui_validate_ssh_key "$1"
    if maestro_tui_append_unique "$1" ssh_keys_value; then
      maestro_tui_write_menu \
        "$extras_value" \
        "$development_mode_value" \
        ssh_keys_value \
        system_packages_value \
        user_packages_value \
        services_value
      maestro_tui_commit_paths "Add SSH key from maestro-menu" "$host_menu_relpath"
    else
      echo "SSH key already present."
    fi
    ;;
  remove-ssh-key)
    [ $# -eq 1 ] || { usage >&2; exit 1; }
    if maestro_tui_remove_value "$1" ssh_keys_value; then
      if [ "${#ssh_keys_value[@]}" -eq 0 ]; then
        echo "At least one SSH key is required." >&2
        exit 1
      fi
      maestro_tui_write_menu \
        "$extras_value" \
        "$development_mode_value" \
        ssh_keys_value \
        system_packages_value \
        user_packages_value \
        services_value
      maestro_tui_commit_paths "Remove SSH key from maestro-menu" "$host_menu_relpath"
    else
      echo "SSH key not found."
    fi
    ;;
  toggle-extras)
    if [ "$extras_value" = "true" ]; then
      extras_value="false"
      commit_message="Disable extras from maestro-menu"
    else
      extras_value="true"
      commit_message="Enable extras from maestro-menu"
    fi
    maestro_tui_write_menu \
      "$extras_value" \
      "$development_mode_value" \
      ssh_keys_value \
      system_packages_value \
      user_packages_value \
      services_value
    maestro_tui_commit_paths "$commit_message" "$host_menu_relpath"
    ;;
  set-development-mode)
    [ $# -eq 1 ] || { usage >&2; exit 1; }
    case "$1" in
      true|false)
        development_mode_value="$1"
        ;;
      *)
        echo "Development Mode value must be true or false." >&2
        exit 1
        ;;
    esac
    maestro_tui_write_menu \
      "$extras_value" \
      "$development_mode_value" \
      ssh_keys_value \
      system_packages_value \
      user_packages_value \
      services_value
    if [ "$development_mode_value" = "true" ]; then
      commit_message="Enable Development Mode from maestro-menu"
    else
      commit_message="Disable Development Mode from maestro-menu"
    fi
    maestro_tui_commit_paths "$commit_message" "$host_menu_relpath"
    ;;
  toggle-development-mode)
    if [ "$development_mode_value" = "true" ]; then
      development_mode_value="false"
      commit_message="Disable Development Mode from maestro-menu"
    else
      development_mode_value="true"
      commit_message="Enable Development Mode from maestro-menu"
    fi
    maestro_tui_write_menu \
      "$extras_value" \
      "$development_mode_value" \
      ssh_keys_value \
      system_packages_value \
      user_packages_value \
      services_value
    maestro_tui_commit_paths "$commit_message" "$host_menu_relpath"
    ;;
  add-system-package)
    [ $# -eq 1 ] || { usage >&2; exit 1; }
    maestro_tui_validate_token "package" "$1"
    if maestro_tui_append_unique "$1" system_packages_value; then
      maestro_tui_write_menu \
        "$extras_value" \
        "$development_mode_value" \
        ssh_keys_value \
        system_packages_value \
        user_packages_value \
        services_value
      maestro_tui_commit_paths "Add system package ${1} from maestro-menu" "$host_menu_relpath"
    else
      echo "System package already present."
    fi
    ;;
  add-user-package)
    [ $# -eq 1 ] || { usage >&2; exit 1; }
    maestro_tui_validate_token "package" "$1"
    if maestro_tui_append_unique "$1" user_packages_value; then
      maestro_tui_write_menu \
        "$extras_value" \
        "$development_mode_value" \
        ssh_keys_value \
        system_packages_value \
        user_packages_value \
        services_value
      maestro_tui_commit_paths "Add user package ${1} from maestro-menu" "$host_menu_relpath"
    else
      echo "User package already present."
    fi
    ;;
  add-service)
    [ $# -eq 1 ] || { usage >&2; exit 1; }
    maestro_tui_validate_token "service" "$1"
    if maestro_tui_append_unique "$1" services_value; then
      maestro_tui_write_menu \
        "$extras_value" \
        "$development_mode_value" \
        ssh_keys_value \
        system_packages_value \
        user_packages_value \
        services_value
      maestro_tui_commit_paths "Enable service ${1} from maestro-menu" "$host_menu_relpath"
    else
      echo "Service already present."
    fi
    ;;
  update-nixpkgs)
    update_input_and_prompt \
      "Update nixpkgs input from maestro-menu" \
      nix flake update nixpkgs
    ;;
  update-home-manager)
    update_input_and_prompt \
      "Update home-manager input from maestro-menu" \
      nix flake update home-manager
    ;;
  update-determinate)
    update_input_and_prompt \
      "Update determinate input from maestro-menu" \
      nix flake update determinate
    ;;
  update-xoa)
    current_xoa_rev="$(lock_rev_for xen-orchestra-ce)"
    echo "Current locked xen-orchestra-ce revision: ${current_xoa_rev:-unknown}"
    echo "Refreshing the xo-nixpkg main input; the appliance selects its configured package channel."
    update_input_and_prompt \
      "Update xen-orchestra-ce input from maestro-menu" \
      nix flake update xen-orchestra-ce
    ;;
  update-all)
    update_input_and_prompt \
      "Update flake inputs from maestro-menu" \
      nix flake update
    ;;
  cleanup-unmanaged-users)
    maestro_run_as_root bash -lc "$(declare -f cleanup_unmanaged_users); cleanup_unmanaged_users $(printf '%q' "$username_value")"
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
