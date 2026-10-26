#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Bootstrap the single Maestro appliance checkout.

set -euo pipefail

readonly BOOTSTRAP_DEFAULT_REPO_URL="https://github.com/closure-labs/maestro.git"
readonly BOOTSTRAP_DEFAULT_BRANCH="main"
readonly BOOTSTRAP_OPERATOR="maestro"

bootstrap_error() {
  printf 'error: %s\n' "$1" >&2
}

bootstrap_info() {
  printf 'info: %s\n' "$1"
}

bootstrap_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif [ -x /run/wrappers/bin/sudo ]; then
    /run/wrappers/bin/sudo "$@"
  else
    sudo "$@"
  fi
}

resolve_script_checkout() {
  local script_dir candidate git_root
  if [ -n "${MAESTRO_SYSTEM_ROOT:-}" ] && [ -f "$MAESTRO_SYSTEM_ROOT/modules/features/operator/cli/_source/lib/common.sh" ]; then
    printf '%s\n' "$MAESTRO_SYSTEM_ROOT"
    return
  fi
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
  candidate="$(cd "$script_dir/.." 2>/dev/null && pwd || true)"
  if [ -f "$candidate/modules/features/operator/cli/_source/lib/common.sh" ]; then
    printf '%s\n' "$candidate"
    return
  fi
  if git_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
    && [ -f "$git_root/modules/features/operator/cli/_source/lib/common.sh" ]
  then
    printf '%s\n' "$git_root"
  fi
}

usage() {
  cat <<'EOF'
Usage: bootstrap.sh [options]

Options:
  --repo-dir PATH       Checkout directory (default: /home/maestro/maestro)
  --repo-url URL        Repository URL
  --branch NAME         Branch to clone or update
  --git-name NAME       Operator Git author name
  --git-email EMAIL     Operator Git author email
  --timezone ZONE       Appliance time zone
  --state-version VER   Initial NixOS state version (default: 26.05)
  --ssh-key KEY         Authorized key for maestro; repeatable
  --enable-flakes       Persist nix-command and flakes before validation
  --skip-check          Skip nix flake check
  --skip-hardware-copy  Keep the checked-in placeholder hardware module
  --first-switch        Perform the first switch (default)
  --no-first-switch     Configure and validate without switching
  --help                Show this help

The hostname, operator, architecture, and flake target are fixed to maestro,
maestro, x86_64-linux, and .#maestro respectively.
EOF
}

enable_flakes() {
  local config_file="/etc/nix/nix.conf"
  local temporary
  if nix show-config experimental-features 2>/dev/null \
    | grep -q nix-command \
    && nix show-config experimental-features 2>/dev/null | grep -q flakes
  then
    return
  fi
  temporary="$(mktemp)"
  if [ -f "$config_file" ]; then
    cp "$config_file" "$temporary"
  fi
  printf '\n# Added by Maestro bootstrap\nexperimental-features = nix-command flakes\n' >> "$temporary"
  bootstrap_sudo install -d -m 0755 /etc/nix
  bootstrap_sudo install -m 0644 "$temporary" "$config_file"
  rm -f "$temporary"
}

collect_existing_keys() {
  local candidate
  for candidate in \
    "${HOME:-}/.ssh/authorized_keys" \
    "/root/.ssh/authorized_keys"
  do
    [ -f "$candidate" ] || continue
    while IFS= read -r key; do
      case "$key" in
        ssh-*|ecdsa-*|sk-*) ssh_keys+=("$key") ;;
      esac
    done < "$candidate"
  done
}

repo_url="${MAESTRO_BOOTSTRAP_SOURCE_REPO_URL:-$BOOTSTRAP_DEFAULT_REPO_URL}"
branch="${MAESTRO_BOOTSTRAP_SOURCE_BRANCH:-}"
repo_dir=""
git_name="Maestro Admin"
git_email="maestro@maestro"
timezone="America/Chicago"
state_version="26.05"
persist_flakes=0
skip_check=0
skip_hardware=0
first_switch=1
declare -a ssh_keys=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo-dir) repo_dir="$2"; shift 2 ;;
    --repo-url) repo_url="$2"; shift 2 ;;
    --branch) branch="$2"; shift 2 ;;
    --git-name) git_name="$2"; shift 2 ;;
    --git-email) git_email="$2"; shift 2 ;;
    --timezone) timezone="$2"; shift 2 ;;
    --state-version) state_version="$2"; shift 2 ;;
    --ssh-key) ssh_keys+=("$2"); shift 2 ;;
    --enable-flakes) persist_flakes=1; shift ;;
    --skip-check) skip_check=1; shift ;;
    --skip-hardware-copy) skip_hardware=1; shift ;;
    --first-switch) first_switch=1; shift ;;
    --no-first-switch) first_switch=0; shift ;;
    --hostname|--username|--profile)
      bootstrap_error "$1 was removed; Maestro uses the fixed maestro appliance identity."
      exit 1
      ;;
    --help|-h)
      usage
      exit
      ;;
    *)
      bootstrap_error "Unknown option: $1"
      usage >&2
      exit 1
      ;;
  esac
done

current_checkout="$(resolve_script_checkout || true)"
if [ -z "$branch" ] && [ -n "$current_checkout" ]; then
  branch="$(git -C "$current_checkout" branch --show-current 2>/dev/null || true)"
fi
branch="${branch:-$BOOTSTRAP_DEFAULT_BRANCH}"
repo_dir="${repo_dir:-/home/$BOOTSTRAP_OPERATOR/maestro}"

if [ "$persist_flakes" -eq 1 ]; then
  enable_flakes
fi

if [ -d "$repo_dir/.git" ]; then
  if [ -n "$(git -C "$repo_dir" status --short)" ]; then
    bootstrap_error "Existing checkout at $repo_dir is dirty."
    exit 1
  fi
  bootstrap_info "Updating checkout in $repo_dir"
  git -C "$repo_dir" fetch origin "$branch"
  git -C "$repo_dir" switch "$branch"
  git -C "$repo_dir" merge --ff-only "origin/$branch"
elif [ -e "$repo_dir" ] && [ -n "$(find "$repo_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  bootstrap_error "$repo_dir exists and is not an empty checkout directory."
  exit 1
else
  bootstrap_info "Cloning $repo_url into $repo_dir"
  if mkdir -p "$(dirname "$repo_dir")" 2>/dev/null; then
    git clone --branch "$branch" "$repo_url" "$repo_dir"
  else
    bootstrap_sudo install -d -m 0755 "$(dirname "$repo_dir")"
    bootstrap_sudo git clone --branch "$branch" "$repo_url" "$repo_dir"
  fi
fi

export MAESTRO_SYSTEM_ROOT="$repo_dir"
# This path belongs to the validated target checkout.
# shellcheck disable=SC1091
. "$repo_dir/modules/features/operator/cli/_source/lib/common.sh"

if [ "${#ssh_keys[@]}" -eq 0 ]; then
  collect_existing_keys
fi
if [ "${#ssh_keys[@]}" -eq 0 ] && [ -t 0 ]; then
  read -r -p "SSH public key for maestro: " key
  [ -z "$key" ] || ssh_keys+=("$key")
fi
if [ "${#ssh_keys[@]}" -eq 0 ]; then
  bootstrap_error "At least one --ssh-key is required to keep SSH access after the first switch."
  exit 1
fi

for key in "${ssh_keys[@]}"; do
  case "$key" in
    ssh-*|ecdsa-*|sk-*) ;;
    *)
      bootstrap_error "Invalid SSH public key: $key"
      exit 1
      ;;
  esac
done

bootstrap_info "Writing fixed appliance settings"
maestro_write_host_settings \
  "$MAESTRO_SETTINGS_FILE" \
  "$repo_dir" \
  "$timezone" \
  "$state_version" \
  "$git_name" \
  "$git_email" \
  ssh_keys

if [ "$skip_hardware" -eq 0 ]; then
  if [ ! -f /etc/nixos/hardware-configuration.nix ]; then
    bootstrap_error "/etc/nixos/hardware-configuration.nix was not found."
    exit 1
  fi
  bootstrap_info "Copying generated hardware configuration"
  cp /etc/nixos/hardware-configuration.nix "$MAESTRO_HARDWARE_FILE"
fi

git -C "$repo_dir" add host/settings.nix host/menu.nix host/hardware-configuration.nix

if [ "$skip_check" -eq 0 ]; then
  bootstrap_info "Validating .#maestro"
  maestro_run_first_install_flake_check
fi

if [ "$first_switch" -eq 1 ]; then
  "$repo_dir/modules/features/operator/cli/_source/maestroctl.sh" apply --first-install
fi

if id -u "$BOOTSTRAP_OPERATOR" >/dev/null 2>&1; then
  bootstrap_sudo chown -R "$BOOTSTRAP_OPERATOR:users" "$repo_dir"
fi

maestro_print_success "Maestro is configured at $repo_dir with target .#maestro."
