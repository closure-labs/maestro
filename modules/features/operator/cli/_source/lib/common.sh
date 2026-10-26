#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

readonly MAESTRO_SYSTEM_ROOT="${MAESTRO_SYSTEM_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
readonly MAESTRO_TARGET="maestro"
readonly MAESTRO_HOST_ROOT="$MAESTRO_SYSTEM_ROOT/host"
readonly MAESTRO_SETTINGS_FILE="$MAESTRO_HOST_ROOT/settings.nix"
readonly MAESTRO_MENU_FILE="$MAESTRO_HOST_ROOT/menu.nix"
readonly MAESTRO_HARDWARE_FILE="$MAESTRO_HOST_ROOT/hardware-configuration.nix"
readonly MAESTRO_DEFAULT_HOSTNAME="maestro"
readonly MAESTRO_DEFAULT_USERNAME="maestro"
# Used by scripts that source this shared library.
# shellcheck disable=SC2034
readonly MAESTRO_DEFAULT_TIMEZONE="America/Chicago"
readonly MAESTRO_DEFAULT_GIT_NAME="Maestro Admin"
readonly MAESTRO_DEFAULT_GIT_EMAIL="maestro@maestro"
readonly MAESTRO_DETERMINATE_SUBSTITUTER="https://install.determinate.systems"
readonly MAESTRO_CACHE_SUBSTITUTER="https://maestro.cachix.org"
readonly MAESTRO_XO_SUBSTITUTER="https://xen-orchestra-ce.cachix.org"
readonly MAESTRO_DEVENV_SUBSTITUTER="https://devenv.cachix.org"
readonly MAESTRO_COMMUNITY_SUBSTITUTER="https://nix-community.cachix.org"
readonly MAESTRO_DETERMINATE_PUBLIC_KEY="cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM="
readonly MAESTRO_CACHE_PUBLIC_KEY="maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0="
readonly MAESTRO_XO_PUBLIC_KEY="xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E="
readonly MAESTRO_DEVENV_PUBLIC_KEY="devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw="
readonly MAESTRO_COMMUNITY_PUBLIC_KEY="nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
readonly -a MAESTRO_TRACKED_PATHS=(
  AGENTS.md
  CHANGELOG.md
  README.md
  docs
  flake.lock
  flake.nix
  host
  installer
  modules
  packer
  pkgs
  scripts
  tests
)

maestro_print_error() {
  printf 'error: %s\n' "$1" >&2
}

maestro_print_warning() {
  printf 'warn: %s\n' "$1" >&2
}

maestro_print_info() {
  printf 'info: %s\n' "$1"
}

maestro_print_success() {
  printf 'ok: %s\n' "$1"
}

maestro_cli_command() {
  if command -v maestroctl >/dev/null 2>&1; then
    printf 'maestroctl\n'
  else
    printf '%s/modules/features/operator/cli/_source/maestroctl.sh\n' "$MAESTRO_SYSTEM_ROOT"
  fi
}

maestro_print_cli_command() {
  local prefix="$1"
  local command
  shift
  command="$(maestro_cli_command)"
  printf '%s %q' "$prefix" "$command"
  printf ' %q' "$@"
  printf '\n'
}

maestro_print_shell_command() {
  local prefix="$1"
  shift
  printf '%s' "$prefix"
  printf ' %q' "$@"
  printf '\n'
}

maestro_nix_quote() {
  printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
}

maestro_system_root() {
  printf '%s\n' "$MAESTRO_SYSTEM_ROOT"
}

maestro_host_settings_file() {
  printf '%s\n' "$MAESTRO_SETTINGS_FILE"
}

maestro_host_menu_file() {
  printf '%s\n' "$MAESTRO_MENU_FILE"
}

maestro_host_hardware_file() {
  printf '%s\n' "$MAESTRO_HARDWARE_FILE"
}

maestro_host_relpath() {
  printf 'host\n'
}

maestro_read_string_file() {
  local key="$1"
  local file="$2"
  [ -f "$file" ] || return 1
  sed -nE "s/^[[:space:]]*(${key}|[A-Za-z0-9_.-]+\\.${key})[[:space:]]*=[[:space:]]*\"([^\"]*)\"[[:space:]]*;.*$/\\2/p" "$file" | tail -n 1
}

maestro_config_string() {
  local key="$1"
  local file value
  for file in "$MAESTRO_MENU_FILE" "$MAESTRO_SETTINGS_FILE"; do
    value="$(maestro_read_string_file "$key" "$file" || true)"
    if [ -n "$value" ]; then
      printf '%s\n' "$value"
      return 0
    fi
  done
  return 1
}

maestro_default_hostname() {
  maestro_config_string hostName || printf '%s\n' "$MAESTRO_DEFAULT_HOSTNAME"
}

maestro_default_target() {
  printf '%s\n' "$MAESTRO_TARGET"
}

maestro_host_output_name() {
  case "${1:-$MAESTRO_TARGET}" in
    "$MAESTRO_TARGET") printf '%s\n' "$MAESTRO_TARGET" ;;
    *) return 1 ;;
  esac
}

maestro_resolve_target_output() {
  maestro_host_output_name "${1:-$MAESTRO_TARGET}"
}

maestro_resolve_target_host() {
  maestro_host_output_name "${1:-$MAESTRO_TARGET}"
}

maestro_require_target_output() {
  local requested="${1:-$MAESTRO_TARGET}"
  if [ "$requested" != "$MAESTRO_TARGET" ]; then
    maestro_print_error "Maestro has one fixed target: $MAESTRO_TARGET."
    return 1
  fi
  printf '%s\n' "$MAESTRO_TARGET"
}

maestro_target_summary_line() {
  maestro_require_target_output "${1:-}" >/dev/null
  printf 'target=maestro host=maestro host_dir=host\n'
}

maestro_host_flake_ref() {
  printf 'path:%s#nixosConfigurations.maestro\n' "$MAESTRO_SYSTEM_ROOT"
}

maestro_nixos_rebuild_flake_ref() {
  printf 'path:%s#maestro\n' "$MAESTRO_SYSTEM_ROOT"
}

maestro_git_user_name() {
  maestro_config_string gitName || printf '%s\n' "$MAESTRO_DEFAULT_GIT_NAME"
}

maestro_git_user_email() {
  maestro_config_string gitEmail || printf '%s\n' "$MAESTRO_DEFAULT_GIT_EMAIL"
}

maestro_cd_root() {
  builtin cd "$MAESTRO_SYSTEM_ROOT" || return
}

maestro_require_git_repo() {
  if [ ! -d "$MAESTRO_SYSTEM_ROOT/.git" ]; then
    maestro_print_error "$MAESTRO_SYSTEM_ROOT is not a git repository."
    return 1
  fi
}

maestro_sudo_bin() {
  if [ -x /run/wrappers/bin/sudo ]; then
    printf '/run/wrappers/bin/sudo\n'
  else
    command -v sudo 2>/dev/null
  fi
}

maestro_run_as_root() {
  local sudo_bin
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return $?
  fi
  sudo_bin="$(maestro_sudo_bin)" || {
    maestro_print_error "Root access is required, but sudo is unavailable."
    return 1
  }
  "$sudo_bin" "$@"
}

maestro_user_exists() {
  [ -n "${1:-}" ] && [ "$1" != root ] && id -u "$1" >/dev/null 2>&1
}

maestro_host_execution_user() {
  local repo_owner
  if maestro_user_exists "${MAESTRO_NH_USER:-}"; then
    printf '%s\n' "$MAESTRO_NH_USER"
  elif maestro_user_exists maestro; then
    printf 'maestro\n'
  elif maestro_user_exists "${SUDO_USER:-}"; then
    printf '%s\n' "$SUDO_USER"
  else
    repo_owner="$(stat -c %U "$MAESTRO_SYSTEM_ROOT" 2>/dev/null || true)"
    maestro_user_exists "$repo_owner" && printf '%s\n' "$repo_owner"
  fi
}

maestro_run_nh() {
  local operator sudo_bin
  command -v nh >/dev/null 2>&1 || {
    maestro_print_error "nh is required for this action."
    return 127
  }
  if [ "$(id -u)" -eq 0 ]; then
    operator="$(maestro_host_execution_user || true)"
    if [ -n "$operator" ]; then
      sudo_bin="$(maestro_sudo_bin)" || return 1
      "$sudo_bin" -H -u "$operator" nh "$@"
      return $?
    fi
  fi
  nh "$@"
}

maestro_status_porcelain() {
  git -C "$MAESTRO_SYSTEM_ROOT" status --short -- "${MAESTRO_TRACKED_PATHS[@]}"
}

maestro_has_changes() {
  [ -n "$(maestro_status_porcelain)" ]
}

maestro_stage_changes() {
  git -C "$MAESTRO_SYSTEM_ROOT" add -A -- "${MAESTRO_TRACKED_PATHS[@]}"
}

maestro_has_staged_changes() {
  ! git -C "$MAESTRO_SYSTEM_ROOT" diff --cached --quiet -- "${MAESTRO_TRACKED_PATHS[@]}"
}

maestro_print_change_summary() {
  printf '=== Configuration Changes ===\n'
  git -C "$MAESTRO_SYSTEM_ROOT" diff HEAD --stat -- "${MAESTRO_TRACKED_PATHS[@]}" 2>/dev/null || true
  maestro_status_porcelain || true
}

maestro_commit_changes() {
  local message="${1:-Record local Maestro changes}"
  local git_name git_email
  git_name="$(maestro_git_user_name)"
  git_email="$(maestro_git_user_email)"
  git -C "$MAESTRO_SYSTEM_ROOT" \
    -c "user.name=$git_name" \
    -c "user.email=$git_email" \
    commit -m "$message"
}

maestro_state_dir() {
  local base="${XDG_STATE_HOME:-${HOME:-$MAESTRO_SYSTEM_ROOT}/.local/state}"
  printf '%s\n' "${MAESTRO_STATE_DIR:-$base/maestro}"
}

maestro_shared_state_dir() {
  printf '%s\n' "${MAESTRO_SHARED_STATE_DIR:-/var/lib/maestro}"
}

maestro_apply_state_file() {
  printf '%s\n' "${MAESTRO_STATUS_FILE:-$(maestro_shared_state_dir)/apply-state.env}"
}

maestro_legacy_apply_state_file() {
  printf '%s/apply-state.env\n' "$(maestro_state_dir)"
}

maestro_rebuild_queue_file() {
  printf '%s\n' "${MAESTRO_REBUILD_QUEUE_FILE:-$(maestro_shared_state_dir)/rebuild-on-boot.env}"
}

maestro_install_state_file() {
  local source="$1"
  local destination="$2"
  local directory
  directory="$(dirname "$destination")"
  if [ "$(id -u)" -eq 0 ] || { [ -d "$directory" ] && [ -w "$directory" ]; }; then
    mkdir -p "$directory"
    install -m 0644 "$source" "$destination"
  else
    maestro_run_as_root install -d -m 0755 "$directory"
    maestro_run_as_root install -m 0644 "$source" "$destination"
  fi
}

maestro_write_apply_state() {
  local result="$1" action="$2" head="$3" first_install="$4" exit_code="$5"
  local temporary
  temporary="$(mktemp)"
  {
    printf 'last_apply_result=%s\n' "$result"
    printf 'last_apply_action=%s\n' "$action"
    printf 'last_apply_hostname=maestro\n'
    printf 'last_apply_head=%s\n' "$head"
    printf 'last_apply_first_install=%s\n' "$first_install"
    printf 'last_apply_exit_code=%s\n' "$exit_code"
    printf 'last_apply_timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$temporary"
  maestro_install_state_file "$temporary" "$(maestro_apply_state_file)"
  rm -f "$temporary"
}

maestro_schedule_rebuild_on_boot() {
  local repo_root="${1:-$MAESTRO_SYSTEM_ROOT}"
  local queue temporary
  queue="$(maestro_rebuild_queue_file)"
  temporary="$(mktemp)"
  {
    printf 'repo_root=%q\n' "$repo_root"
    printf 'scheduled_at=%q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$temporary"
  maestro_install_state_file "$temporary" "$queue"
  rm -f "$temporary"
}

maestro_validate_hostname() {
  [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*$ ]] || {
    maestro_print_error "Invalid hostname '$1'."
    return 1
  }
}

maestro_validate_username() {
  [ "$1" = "$MAESTRO_DEFAULT_USERNAME" ] || {
    maestro_print_error "The appliance operator is fixed to '$MAESTRO_DEFAULT_USERNAME'."
    return 1
  }
}

maestro_default_editor() {
  printf '%s\n' "${VISUAL:-${EDITOR:-vi}}"
}

maestro_prompt_with_default() {
  local prompt="$1" default="$2" reply=""
  if [ ! -t 0 ]; then
    printf '%s\n' "$default"
    return
  fi
  read -r -p "$prompt [$default]: " reply
  printf '%s\n' "${reply:-$default}"
}

maestro_confirm() {
  local reply
  [ -t 0 ] || return 1
  read -r -p "$1 [y/N]: " reply
  [[ "$reply" =~ ^([yY]|yes|YES)$ ]]
}

maestro_require_clean_repo() {
  maestro_require_git_repo
  if maestro_has_changes; then
    maestro_print_error "Tracked Maestro files have uncommitted changes."
    maestro_status_porcelain >&2 || true
    return 1
  fi
}

maestro_service_exists() {
  local state
  state="$(systemctl show "$1" -p LoadState --value 2>/dev/null || true)"
  [ -n "$state" ] && [ "$state" != not-found ]
}

maestro_service_state() {
  if ! maestro_service_exists "$1"; then
    printf 'unavailable\n'
  elif systemctl is-active "$1" >/dev/null 2>&1; then
    printf 'active\n'
  else
    printf 'inactive\n'
  fi
}

maestro_redis_service_name() {
  local unit
  for unit in redis-xo.service valkey-xo.service; do
    if maestro_service_exists "$unit"; then
      printf '%s\n' "$unit"
      return
    fi
  done
  printf 'redis-xo.service\n'
}

maestro_render_status() {
  local redis dirty_count=0
  redis="$(maestro_redis_service_name)"
  if maestro_require_git_repo >/dev/null 2>&1; then
    dirty_count="$(maestro_status_porcelain | wc -l | tr -d ' ')"
  fi
  printf 'Repo root: %s\n' "$MAESTRO_SYSTEM_ROOT"
  printf 'Target: maestro\n'
  printf 'xo-server.service: %s\n' "$(maestro_service_state xo-server.service)"
  printf '%s: %s\n' "$redis" "$(maestro_service_state "$redis")"
  if [ "$dirty_count" -eq 0 ]; then
    printf 'Git state: clean\n'
  else
    printf 'Git state: dirty (%s tracked path changes)\n' "$dirty_count"
  fi
}

maestro_append_first_install_nix_options() {
  local -n command_ref="$1"
  command_ref+=(
    --option extra-experimental-features "nix-command flakes"
    --option extra-substituters "$MAESTRO_DETERMINATE_SUBSTITUTER $MAESTRO_CACHE_SUBSTITUTER $MAESTRO_XO_SUBSTITUTER $MAESTRO_DEVENV_SUBSTITUTER $MAESTRO_COMMUNITY_SUBSTITUTER"
    --option extra-trusted-public-keys "$MAESTRO_DETERMINATE_PUBLIC_KEY $MAESTRO_CACHE_PUBLIC_KEY $MAESTRO_XO_PUBLIC_KEY $MAESTRO_DEVENV_PUBLIC_KEY $MAESTRO_COMMUNITY_PUBLIC_KEY"
  )
}

maestro_build_first_install_switch_command() {
  # The caller passes the name of an array to populate.
  # shellcheck disable=SC2178
  local -n command_ref="$1"
  command_ref=(
    nixos-rebuild switch
    --flake "$(maestro_nixos_rebuild_flake_ref)"
    -L
  )
  maestro_append_first_install_nix_options "$1"
}

maestro_run_first_install_flake_check() {
  local -a command=(
    nix flake check
    --no-write-lock-file
    "path:$MAESTRO_SYSTEM_ROOT"
  )
  maestro_append_first_install_nix_options command
  "${command[@]}"
}

maestro_print_first_switch_commands() {
  local -a command
  maestro_build_first_install_switch_command command
  maestro_print_cli_command "Repo helper:" apply --first-install
  maestro_print_shell_command "nixos-rebuild:" "${command[@]}"
}

maestro_build_nh_command() {
  # The caller passes the name of an array to populate.
  # shellcheck disable=SC2178
  local -n command_ref="$1"
  local action="$2" ask="$3" cores="$4" verbose="$5"
  shift 5
  command_ref=(
    os "$action"
    "$(maestro_host_flake_ref)"
    -L
  )
  if [ -n "$(maestro_sudo_bin || true)" ]; then
    command_ref+=(--elevation-strategy "$(maestro_sudo_bin)")
  fi
  [ "$ask" -eq 0 ] || command_ref+=(--ask)
  [ -z "$cores" ] || command_ref+=(--cores "$cores")
  [ "$verbose" -eq 0 ] || command_ref+=(--verbose)
  command_ref+=("$@")
}

maestro_write_host_settings() {
  local settings_file="$1" repo_dir="$2" timezone="$3" state_version="$4"
  local git_name="$5" git_email="$6" keys_name="$7"
  local -n keys_ref="$keys_name"
  local key
  {
    printf '%s\n' '# SPDX-License-Identifier: Apache-2.0'
    printf '%s\n' '# Generated by bootstrap; edit this file for appliance policy.'
    printf '%s\n' '{lib, ...}: {'
    printf '  networking.hostName = "maestro";\n'
    printf '  time.timeZone = %s;\n' "$(maestro_nix_quote "$timezone")"
    printf '  system.stateVersion = %s;\n\n' "$(maestro_nix_quote "$state_version")"
    printf '  boot.loader.systemd-boot.enable = true;\n'
    printf '  boot.loader.efi.canTouchEfiVariables = true;\n'
    printf '  networking.firewall.allowedTCPPorts = [80 443];\n\n'
    printf '  maestro.operator = {\n'
    printf '    repoDir = %s;\n' "$(maestro_nix_quote "$repo_dir")"
    printf '    gitName = %s;\n' "$(maestro_nix_quote "$git_name")"
    printf '    gitEmail = %s;\n' "$(maestro_nix_quote "$git_email")"
    printf '    sshKeys = lib.mkDefault [\n'
    for key in "${keys_ref[@]}"; do
      printf '      %s\n' "$(maestro_nix_quote "$key")"
    done
    printf '    ];\n'
    printf '    enableExtras = lib.mkDefault false;\n'
    printf '    developmentMode = lib.mkDefault false;\n'
    printf '    menuAutoStart = false;\n'
    printf '    sudoNoPassword = true;\n'
    printf '    systemPackages = [];\n'
    printf '    userPackages = [];\n'
    printf '  };\n\n'
    printf '  maestro.xo = {\n'
    printf '    enable = true;\n'
    printf '    httpHost = "0.0.0.0";\n'
    printf '    tls = { enable = true; autoCert = true; };\n'
    printf '    storage = {\n'
    printf '      enableNFS = true;\n'
    printf '      enableCIFS = true;\n'
    printf '      enableVHD = true;\n'
    printf '      mountsDir = "/var/lib/xo/mounts";\n'
    printf '    };\n'
    printf '  };\n'
    printf '}\n'
  } > "$settings_file"
}
