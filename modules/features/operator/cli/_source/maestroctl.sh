#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Canonical Maestro operator CLI

set -euo pipefail

readonly MAESTROCTL_VERSION="5.0.0"

resolve_repo_root() {
  local candidate search_dir script_dir git_root

  if [ -n "${MAESTRO_SYSTEM_ROOT:-}" ] && [ -f "$MAESTRO_SYSTEM_ROOT/modules/features/operator/cli/_source/lib/common.sh" ]; then
    printf '%s\n' "$MAESTRO_SYSTEM_ROOT"
    return
  fi

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  candidate="$(cd "$script_dir/../../../../.." && pwd)"
  if [ -f "$candidate/modules/features/operator/cli/_source/lib/common.sh" ]; then
    printf '%s\n' "$candidate"
    return
  fi

  if git_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
    && [ -f "$git_root/modules/features/operator/cli/_source/lib/common.sh" ]
  then
    printf '%s\n' "$git_root"
    return
  fi

  search_dir="${PWD:-}"
  while [ -n "$search_dir" ] && [ "$search_dir" != / ]; do
    if [ -f "$search_dir/modules/features/operator/cli/_source/lib/common.sh" ]; then
      printf '%s\n' "$search_dir"
      return
    fi
    search_dir="$(dirname "$search_dir")"
  done

  maestro_root_error="Could not find a Maestro checkout. Run from it or set MAESTRO_SYSTEM_ROOT."
  printf 'error: %s\n' "$maestro_root_error" >&2
  exit 1
}

REPO_ROOT="$(resolve_repo_root)"
export MAESTRO_SYSTEM_ROOT="$REPO_ROOT"
# shellcheck source=modules/features/operator/cli/_source/lib/common.sh
. "$REPO_ROOT/modules/features/operator/cli/_source/lib/common.sh"

show_help() {
  cat <<'EOF'
Usage:
  maestroctl help
  maestroctl version
  maestroctl status [--json]
  maestroctl apply [--build|--dry-run|--first-install] [--ask] [--cores N] [--verbose] [-- ...]
  maestroctl boot [--ask] [--cores N] [--verbose] [-- ...]
  maestroctl rollback [--ask]
  maestroctl commit [MESSAGE]
  maestroctl diff [--json|--staged]
  maestroctl history
  maestroctl host show [--json]
  maestroctl host edit
  maestroctl host development-mode [status|on|off|toggle]
  maestroctl update flake [--preview] [--ask]
  maestroctl update xoa [--preview] [--ask]
  maestroctl xo logs
  maestroctl generations list

Maestro has one canonical flake target: .#maestro.
EOF
}

show_apply_help() {
  cat <<'EOF'
Usage: maestroctl apply [--build|--dry-run|--first-install] [--ask] [--cores N] [--verbose] [-- ...]
       maestroctl boot [--ask] [--cores N] [--verbose] [-- ...]
       maestroctl rollback [--ask]

All operations target .#maestro. Target-selection flags are intentionally unsupported.
EOF
}

show_update_help() {
  cat <<'EOF'
Usage: maestroctl update flake [--preview] [--ask]
       maestroctl update xoa [--preview] [--ask]
EOF
}

json_quote() {
  printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g')"
}

show_diff_json() {
  local first=1 line status path
  printf '{\n  "changes": ['
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    status="${line:0:2}"
    path="${line:3}"
    [ "$first" -eq 1 ] || printf ','
    printf '\n    {"status": %s, "path": %s}' "$(json_quote "$status")" "$(json_quote "$path")"
    first=0
  done < <(maestro_status_porcelain || true)
  [ "$first" -eq 1 ] || printf '\n  '
  printf ']\n}\n'
}

show_status() {
  case "${1:-}" in
    "")
      maestro_render_status
      ;;
    --json)
      "$MAESTRO_SYSTEM_ROOT/modules/features/operator/menu/_source/backend/state.sh" --json
      ;;
    --help|-h)
      printf 'Usage: maestroctl status [--json]\n'
      ;;
    *)
      maestro_print_error "Unknown status option: $1"
      return 1
      ;;
  esac
}

host_show() {
  local json=0 development=false
  case "${1:-}" in
    "") ;;
    --json) json=1 ;;
    --help|-h)
      printf 'Usage: maestroctl host show [--json]\n'
      return
      ;;
    *)
      maestro_print_error "host show does not accept a target; Maestro always uses maestro."
      return 1
      ;;
  esac
  development="$(
    sed -nE 's/^[[:space:]]*developmentMode[[:space:]]*=[[:space:]]*(true|false)[[:space:]]*;.*/\1/p' \
      "$MAESTRO_MENU_FILE" "$MAESTRO_SETTINGS_FILE" | head -n 1
  )"
  development="${development:-false}"
  if [ "$json" -eq 1 ]; then
    printf '{\n'
    printf '  "host": "maestro",\n'
    printf '  "target": "maestro",\n'
    printf '  "directory": "host",\n'
    printf '  "username": "maestro",\n'
    printf '  "hostname": %s,\n' "$(json_quote "$(maestro_default_hostname)")"
    printf '  "developmentMode": %s,\n' "$development"
    printf '  "settingsFile": "host/settings.nix",\n'
    printf '  "xoConfigPattern": "/etc/xo-server/config.nixos-*.toml",\n'
    printf '  "menuFile": "host/menu.nix",\n'
    printf '  "hardwareFile": "host/hardware-configuration.nix"\n'
    printf '}\n'
  else
    printf 'Host: maestro\n'
    printf 'Target: .#maestro\n'
    printf 'Hostname: %s\n' "$(maestro_default_hostname)"
    printf 'Operator: maestro\n'
    printf 'Development Mode: %s\n' "$development"
    printf 'Settings: host/settings.nix\n'
    printf 'XO configuration: generated /etc/xo-server/config.nixos-*.toml\n'
    printf 'Menu overrides: host/menu.nix\n'
    printf 'Hardware: host/hardware-configuration.nix\n'
  fi
}

host_development_mode() {
  local mode="${1:-status}" value
  case "$mode" in
    status)
      value="$(
        sed -nE 's/^[[:space:]]*developmentMode[[:space:]]*=[[:space:]]*(true|false)[[:space:]]*;.*/\1/p' \
          "$MAESTRO_MENU_FILE" "$MAESTRO_SETTINGS_FILE" | head -n 1
      )"
      printf 'Development Mode for maestro: %s\n' "${value:-false}"
      ;;
    on|enable|true)
      "$MAESTRO_SYSTEM_ROOT/modules/features/operator/menu/_source/backend/action.sh" set-development-mode true
      ;;
    off|disable|false)
      "$MAESTRO_SYSTEM_ROOT/modules/features/operator/menu/_source/backend/action.sh" set-development-mode false
      ;;
    toggle)
      "$MAESTRO_SYSTEM_ROOT/modules/features/operator/menu/_source/backend/action.sh" toggle-development-mode
      ;;
    --help|-h)
      printf 'Usage: maestroctl host development-mode [status|on|off|toggle]\n'
      ;;
    *)
      maestro_print_error "Unknown Development Mode action: $mode"
      return 1
      ;;
  esac
}

dispatch_host() {
  local subcommand="${1:-}"
  shift || true
  case "$subcommand" in
    show) host_show "$@" ;;
    edit)
      [ "$#" -eq 0 ] || {
        maestro_print_error "host edit does not accept a target."
        return 1
      }
      exec "$(maestro_default_editor)" \
        "$MAESTRO_SETTINGS_FILE" \
        "$MAESTRO_MENU_FILE"
      ;;
    development-mode) host_development_mode "$@" ;;
    help|--help|-h)
      printf 'Usage: maestroctl host {show|edit|development-mode}\n'
      ;;
    add|list|select-vm)
      maestro_print_error "maestroctl host $subcommand was removed; this repository defines only maestro."
      return 1
      ;;
    *)
      maestro_print_error "Unknown host command: ${subcommand:-<missing>}"
      return 1
      ;;
  esac
}

commit_changes() {
  local message="${1:-}"
  [ "$#" -le 1 ] || {
    maestro_print_error "commit accepts at most one message."
    return 1
  }
  maestro_require_git_repo
  maestro_cd_root
  maestro_stage_changes
  if ! maestro_has_staged_changes; then
    maestro_print_success "No changes to commit."
    return
  fi
  maestro_commit_changes "${message:-Record local Maestro changes}"
}

show_diff() {
  local staged=0
  case "${1:-}" in
    "") ;;
    --json)
      show_diff_json
      return
      ;;
    --staged) staged=1 ;;
    --help|-h)
      printf 'Usage: maestroctl diff [--json|--staged]\n'
      return
      ;;
    *)
      maestro_print_error "Unknown diff option: $1"
      return 1
      ;;
  esac
  if [ "$staged" -eq 1 ]; then
    git -C "$MAESTRO_SYSTEM_ROOT" diff --cached -- "${MAESTRO_TRACKED_PATHS[@]}"
  else
    maestro_print_change_summary
    git -C "$MAESTRO_SYSTEM_ROOT" diff -- "${MAESTRO_TRACKED_PATHS[@]}"
  fi
}

show_history() {
  [ "$#" -eq 0 ] || {
    maestro_print_error "history accepts no arguments."
    return 1
  }
  git -C "$MAESTRO_SYSTEM_ROOT" log --oneline --decorate --graph -10 -- "${MAESTRO_TRACKED_PATHS[@]}"
}

run_apply_config() {
  local rebuild_action="switch" record_action="switch"
  local first_install=false rollback=false dry_run=0 ask=0 verbose=0 cores=""
  local current_head exit_code=0 sudo_bin
  local -a extra_args=() rebuild_cmd=() run_cmd=()

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --target|--hostname)
        maestro_print_error "Target selection was removed; use the fixed .#maestro target."
        return 1
        ;;
      --build)
        rebuild_action=build
        record_action=build
        shift
        ;;
      --boot)
        rebuild_action=boot
        record_action=boot
        shift
        ;;
      --dry-run)
        dry_run=1
        record_action=dry-run
        shift
        ;;
      --rollback)
        rollback=true
        record_action=rollback
        shift
        ;;
      --first-install)
        first_install=true
        shift
        ;;
      --ask)
        ask=1
        shift
        ;;
      --cores)
        [ "$#" -ge 2 ] || {
          maestro_print_error "--cores requires a value."
          return 1
        }
        cores="$2"
        shift 2
        ;;
      --verbose)
        verbose=1
        shift
        ;;
      --help|-h)
        show_apply_help
        return
        ;;
      --)
        shift
        extra_args+=("$@")
        break
        ;;
      *)
        extra_args+=("$1")
        shift
        ;;
    esac
  done

  maestro_cd_root
  current_head="$(git rev-parse HEAD 2>/dev/null || true)"

  if [ "$rollback" = true ]; then
    if [ "$ask" -eq 1 ] && ! maestro_confirm "Roll back the current system generation"; then
      maestro_print_warning "Rollback cancelled."
      return 1
    fi
    rebuild_cmd=(nixos-rebuild switch --rollback -L)
  elif [ "$first_install" = true ] && [ "$record_action" = switch ]; then
    maestro_build_first_install_switch_command rebuild_cmd
    rebuild_cmd+=("${extra_args[@]}")
  else
    maestro_build_nh_command rebuild_cmd "$rebuild_action" "$ask" "$cores" "$verbose"
    [ "$dry_run" -eq 0 ] || rebuild_cmd+=(--dry)
    if [ "${#extra_args[@]}" -gt 0 ]; then
      rebuild_cmd+=(-- "${extra_args[@]}")
    fi
  fi

  if [ "$rollback" = true ] || { [ "$first_install" = true ] && [ "$record_action" = switch ]; }; then
    if [ "$(id -u)" -ne 0 ]; then
      sudo_bin="$(maestro_sudo_bin)" || return 1
      run_cmd=("$sudo_bin" "${rebuild_cmd[@]}")
    else
      run_cmd=("${rebuild_cmd[@]}")
    fi
  else
    run_cmd=(maestro_run_nh "${rebuild_cmd[@]}")
  fi

  printf 'Running:'
  printf ' %q' "${run_cmd[@]}"
  printf '\n'

  if "${run_cmd[@]}"; then
    maestro_write_apply_state success "$record_action" "$current_head" "$first_install" 0
  else
    exit_code="$?"
    maestro_write_apply_state failed "$record_action" "$current_head" "$first_install" "$exit_code"
    return "$exit_code"
  fi
}

preview_update() {
  local temporary
  temporary="$(mktemp)"
  cp "$MAESTRO_SYSTEM_ROOT/flake.lock" "$temporary"
  if [ "$#" -gt 0 ]; then
    nix flake update --output-lock-file "$temporary" "$@"
  else
    nix flake update --output-lock-file "$temporary"
  fi
  if git diff --no-index --quiet -- flake.lock "$temporary"; then
    maestro_print_success "No lock-file changes found."
  else
    git diff --no-index -- flake.lock "$temporary" || true
  fi
  rm -f "$temporary"
}

update_input() {
  local input="${1:-}"
  shift || true
  local preview=0 ask=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --preview) preview=1; shift ;;
      --ask) ask=1; shift ;;
      --help|-h) show_update_help; return ;;
      --target|--hostname)
        maestro_print_error "Target selection was removed; updates apply to the maestro flake."
        return 1
        ;;
      *)
        maestro_print_error "Unknown update option: $1"
        return 1
        ;;
    esac
  done
  maestro_cd_root
  if [ "$ask" -eq 1 ] && ! maestro_confirm "Update ${input:-all flake inputs}"; then
    maestro_print_warning "Update cancelled."
    return 1
  fi
  if [ "$preview" -eq 1 ]; then
    if [ -n "$input" ]; then preview_update "$input"; else preview_update; fi
    return
  fi
  if [ -n "$input" ]; then
    nix flake update "$input"
  else
    nix flake update
  fi
  maestro_print_success "Flake inputs updated."
  maestro_print_cli_command "Next:" apply
  maestro_print_cli_command "Safer path:" boot
}

dispatch_update() {
  local subcommand="${1:-}"
  shift || true
  case "$subcommand" in
    flake) update_input "" "$@" ;;
    xoa) update_input xen-orchestra-ce "$@" ;;
    help|--help|-h) show_update_help ;;
    *)
      maestro_print_error "Unknown update command: ${subcommand:-<missing>}"
      return 1
      ;;
  esac
}

dispatch_xo() {
  case "${1:-}" in
    logs)
      [ "$#" -eq 1 ] || {
        maestro_print_error "xo logs accepts no arguments."
        return 1
      }
      exec journalctl -u xo-server -u "$(maestro_redis_service_name)" -e -f
      ;;
    help|--help|-h)
      printf 'Usage: maestroctl xo logs\n'
      ;;
    *)
      maestro_print_error "Unknown xo command: ${1:-<missing>}"
      return 1
      ;;
  esac
}

dispatch_generations() {
  case "${1:-}" in
    list)
      [ "$#" -eq 1 ] || {
        maestro_print_error "generations list accepts no arguments."
        return 1
      }
      maestro_run_as_root nix-env --list-generations -p /nix/var/nix/profiles/system
      ;;
    help|--help|-h)
      printf 'Usage: maestroctl generations list\n'
      ;;
    *)
      maestro_print_error "Unknown generations command: ${1:-<missing>}"
      return 1
      ;;
  esac
}

main() {
  local command="${1:-help}"
  shift || true
  case "$command" in
    help|--help|-h) show_help ;;
    version) printf 'maestroctl %s\n' "$MAESTROCTL_VERSION" ;;
    status) show_status "$@" ;;
    apply) run_apply_config "$@" ;;
    boot) run_apply_config --boot "$@" ;;
    rollback) run_apply_config --rollback "$@" ;;
    commit) commit_changes "$@" ;;
    diff) show_diff "$@" ;;
    history) show_history "$@" ;;
    host) dispatch_host "$@" ;;
    update) dispatch_update "$@" ;;
    xo) dispatch_xo "$@" ;;
    generations) dispatch_generations "$@" ;;
    *)
      maestro_print_error "Unknown command: $command"
      show_help >&2
      return 1
      ;;
  esac
}

main "$@"
