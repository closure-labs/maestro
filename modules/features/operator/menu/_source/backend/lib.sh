#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

TUI_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=modules/features/operator/cli/_source/lib/common.sh
. "$TUI_LIB_DIR/../../../cli/_source/lib/common.sh"

maestro_tui_quote() {
  printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
}

maestro_tui_has_key() {
  local key="$1"
  local file="$2"
  [ -f "$file" ] && grep -Eq "^[[:space:]]*([A-Za-z0-9_.-]+\\.)?${key}[[:space:]]*=" "$file"
}

maestro_tui_read_string_file() {
  local key="$1"
  local file="$2"

  [ -f "$file" ] || return 1
  sed -nE "s/^[[:space:]]*([A-Za-z0-9_.-]+\\.)?${key}[[:space:]]*=[[:space:]]*\"([^\"]*)\"[[:space:]]*;.*$/\\2/p" "$file" | tail -n 1
}

maestro_tui_read_bool_file() {
  local key="$1"
  local file="$2"

  [ -f "$file" ] || return 1
  sed -nE "s/^[[:space:]]*([A-Za-z0-9_.-]+\\.)?${key}[[:space:]]*=[[:space:]]*(lib\\.mkDefault[[:space:]]+)?(true|false)[[:space:]]*;.*$/\\3/p" "$file" | tail -n 1
}

maestro_tui_read_list_file() {
  local key="$1"
  local file="$2"

  [ -f "$file" ] || return 0
  awk -v key="$key" '
    function emit_strings(text, line) {
      line = text
      while (match(line, /"[^"]+"/)) {
        print substr(line, RSTART + 1, RLENGTH - 2)
        line = substr(line, RSTART + RLENGTH)
      }
    }
    $0 ~ "^[[:space:]]*([A-Za-z0-9_.-]+\\.)?" key "[[:space:]]*=[[:space:]]*(lib\\.mk(Default|Force)[[:space:]]+)?\\[" {
      line = $0
      sub(/^.*\[/, "", line)
      if (line ~ /\]/) {
        sub(/\].*$/, "", line)
        emit_strings(line)
        exit
      }
      emit_strings(line)
      in_list = 1
      next
    }
    in_list && $0 ~ /^[[:space:]]*\];/ {
      exit
    }
    in_list {
      emit_strings($0)
    }
  ' "$file"
}

maestro_tui_xo_tls_enabled() {
  local config_file="$1"

  [ -r "$config_file" ] || return 1
  awk '
    /^\[\[http\.listen\]\][[:space:]]*$/ {
      if (in_listener && has_cert && has_key) {
        found = 1
      }
      in_listener = 1
      has_cert = 0
      has_key = 0
      next
    }
    /^\[/ {
      if (in_listener && has_cert && has_key) {
        found = 1
      }
      in_listener = 0
    }
    in_listener && /^[[:space:]]*cert[[:space:]]*=/ {
      has_cert = 1
    }
    in_listener && /^[[:space:]]*key[[:space:]]*=/ {
      has_key = 1
    }
    END {
      if (in_listener && has_cert && has_key) {
        found = 1
      }
      exit found ? 0 : 1
    }
  ' "$config_file"
}

maestro_tui_first_string() {
  local key="$1"
  shift
  local file
  local value

  for file in "$@"; do
    value="$(maestro_tui_read_string_file "$key" "$file")"
    if [ -n "$value" ]; then
      printf '%s\n' "$value"
      return 0
    fi
  done

  return 1
}

maestro_tui_first_bool() {
  local key="$1"
  shift
  local file
  local value

  for file in "$@"; do
    value="$(maestro_tui_read_bool_file "$key" "$file")"
    if [ "$value" = "true" ] || [ "$value" = "false" ]; then
      printf '%s\n' "$value"
      return 0
    fi
  done

  return 1
}

maestro_tui_hostname() {
  maestro_tui_first_string hostName "$(maestro_host_menu_file)" "$(maestro_host_settings_file)" \
    || printf '%s\n' "$MAESTRO_DEFAULT_HOSTNAME"
}

maestro_tui_username() {
  printf '%s\n' "$MAESTRO_DEFAULT_USERNAME"
}

maestro_tui_timezone() {
  maestro_tui_first_string timeZone "$(maestro_host_menu_file)" "$(maestro_host_settings_file)" \
    || printf '%s\n' "$MAESTRO_DEFAULT_TIMEZONE"
}

maestro_tui_enable_extras() {
  maestro_tui_first_bool enableExtras "$(maestro_host_menu_file)" "$(maestro_host_settings_file)" || printf '%s\n' false
}

maestro_tui_development_mode() {
  maestro_tui_first_bool developmentMode "$(maestro_host_menu_file)" "$(maestro_host_settings_file)" || printf '%s\n' false
}

maestro_tui_ssh_keys() {
  local file

  for file in "$(maestro_host_menu_file)" "$(maestro_host_settings_file)"; do
    if maestro_tui_has_key sshKeys "$file"; then
      maestro_tui_read_list_file sshKeys "$file"
      return 0
    fi
  done
}

maestro_tui_extra_system_packages() {
  maestro_tui_read_list_file extraSystemPackages "$(maestro_host_menu_file)"
}

maestro_tui_extra_user_packages() {
  maestro_tui_read_list_file extraUserPackages "$(maestro_host_menu_file)"
}

maestro_tui_enabled_services() {
  maestro_tui_read_list_file enabledServices "$(maestro_host_menu_file)"
}

maestro_tui_dirty_count() {
  git -C "$MAESTRO_SYSTEM_ROOT" status --short -- "${MAESTRO_TRACKED_PATHS[@]}" | wc -l | tr -d ' '
}

maestro_tui_write_menu() {
  local extras="$1"
  local development_mode="$2"
  local -n ssh_keys_ref="$3"
  local -n system_packages_ref="$4"
  local -n user_packages_ref="$5"
  local -n services_ref="$6"
  local menu_file

  menu_file="$(maestro_host_menu_file)"

  {
    echo "# SPDX-License-Identifier: Apache-2.0"
    echo "# Managed by maestro-menu"
    echo "{ ... }:"
    echo "{"
    echo "  maestro.operator = {"
    echo "    sshKeys = ["
    for key in "${ssh_keys_ref[@]}"; do
      echo "      $(maestro_tui_quote "$key")"
    done
    echo "    ];"
    echo ""
    echo "    enableExtras = ${extras};"
    echo "    developmentMode = ${development_mode};"
    echo ""
    echo "    menu = {"
    echo "      extraSystemPackages = ["
    for package_name in "${system_packages_ref[@]}"; do
      echo "        $(maestro_tui_quote "$package_name")"
    done
    echo "      ];"
    echo ""
    echo "      extraUserPackages = ["
    for package_name in "${user_packages_ref[@]}"; do
      echo "        $(maestro_tui_quote "$package_name")"
    done
    echo "      ];"
    echo ""
    echo "      enabledServices = ["
    for service_name in "${services_ref[@]}"; do
      echo "        $(maestro_tui_quote "$service_name")"
    done
    echo "      ];"
    echo "    };"
    echo "  };"
    echo "}"
  } > "$menu_file"
}

maestro_tui_append_unique() {
  local value="$1"
  shift
  local -n items_ref="$1"
  local item

  for item in "${items_ref[@]}"; do
    if [ "$item" = "$value" ]; then
      return 1
    fi
  done

  items_ref+=("$value")
  return 0
}

maestro_tui_validate_token() {
  local label="$1"
  local value="$2"

  if [[ -z "$value" || "$value" =~ [[:space:]] ]]; then
    echo "Invalid ${label}: '${value}'" >&2
    echo "${label} values must be non-empty and contain no whitespace." >&2
    exit 1
  fi
}

maestro_tui_validate_ssh_key() {
  local value="$1"

  if [[ "$value" != ssh-* && "$value" != ecdsa-* && "$value" != sk-* ]]; then
    echo "SSH key must be a public key line starting with ssh-, ecdsa-, or sk-." >&2
    exit 1
  fi
}

maestro_tui_remove_value() {
  local value="$1"
  shift
  # The caller passes the name of the array to mutate.
  # shellcheck disable=SC2178
  local -n items_ref="$1"
  local filtered=()
  local found=1
  local item

  for item in "${items_ref[@]}"; do
    if [ "$item" = "$value" ]; then
      found=0
      continue
    fi
    filtered+=("$item")
  done

  items_ref=("${filtered[@]}")
  return "$found"
}

maestro_tui_commit_paths() {
  local message="$1"
  shift

  if [ -z "$(git -C "$MAESTRO_SYSTEM_ROOT" status --short -- "$@")" ]; then
    echo "No tracked changes to commit."
    return 0
  fi

  git -C "$MAESTRO_SYSTEM_ROOT" add -- "$@"
  git -C "$MAESTRO_SYSTEM_ROOT" commit -m "$message"
}
