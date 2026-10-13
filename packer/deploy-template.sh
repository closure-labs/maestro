#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT=${MAESTRO_SYSTEM_ROOT:-}
if [[ -z "$REPO_ROOT" ]]; then
  if git_root=$(git rev-parse --show-toplevel 2>/dev/null); then
    REPO_ROOT=$git_root
  elif [[ -f "$SCRIPT_DIR/../flake.nix" ]]; then
    REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
  else
    printf 'Run this command from a Maestro checkout or set MAESTRO_SYSTEM_ROOT.\n' >&2
    exit 1
  fi
fi
PACKER_ROOT=${MAESTRO_PACKER_ROOT:-$REPO_ROOT/packer}
[[ -f "$PACKER_ROOT/builds.pkr.hcl" ]] || {
  printf 'Maestro Packer sources were not found at %s.\n' "$PACKER_ROOT" >&2
  exit 1
}
config_file=${PACKER_CONFIG_FILE:-$PACKER_ROOT/local.pkrvars.json}
configure_only=0

remote_host=
remote_username=
sr_iso_name=
sr_name=
network_name=
export_network_name=
template_name=
memory_mb=
disk_size_mb=
operator_key=${HOME:-}/.ssh/id_ed25519.pub
repo_url=https://github.com/closure-labs/maestro.git
repo_branch=main

usage() {
  cat <<'EOF'
Usage: deploy-template.sh [options]

Download the prebuilt Maestro installer and create one native XCP-ng template.

Options:
  --host HOST             XCP-ng pool master
  --username USER         XCP-ng API username
  --iso-sr NAME           ISO storage repository
  --sr NAME               template disk storage repository
  --network NAME          DHCP-enabled installer network
  --export-network NAME   network retained by the template
  --template-name NAME    native template name
  --memory-mb MIB         template memory (minimum 4096)
  --disk-size-mb MIB      template disk size (minimum 20480)
  --operator-key FILE     SSH public key for the maestro operator
  --repo-url URL          Maestro repository installed into the template
  --branch NAME           Maestro repository branch
  --config FILE           non-secret Packer JSON configuration
  --configure-only        save settings without deploying
  -h, --help              show this help

The XCP-ng password is never written to disk. Set PKR_VAR_remote_password for
unattended use; otherwise the script requests it without echo.
EOF
}

need_argument() {
  [[ "$#" -ge 2 && -n "$2" ]] || {
    printf '%s requires a value.\n' "$1" >&2
    exit 2
  }
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --host) need_argument "$@"; remote_host=$2; shift 2 ;;
    --username) need_argument "$@"; remote_username=$2; shift 2 ;;
    --iso-sr) need_argument "$@"; sr_iso_name=$2; shift 2 ;;
    --sr) need_argument "$@"; sr_name=$2; shift 2 ;;
    --network) need_argument "$@"; network_name=$2; shift 2 ;;
    --export-network) need_argument "$@"; export_network_name=$2; shift 2 ;;
    --template-name) need_argument "$@"; template_name=$2; shift 2 ;;
    --memory-mb) need_argument "$@"; memory_mb=$2; shift 2 ;;
    --disk-size-mb) need_argument "$@"; disk_size_mb=$2; shift 2 ;;
    --operator-key) need_argument "$@"; operator_key=$2; shift 2 ;;
    --repo-url) need_argument "$@"; repo_url=$2; shift 2 ;;
    --branch) need_argument "$@"; repo_branch=$2; shift 2 ;;
    --config) need_argument "$@"; config_file=$2; shift 2 ;;
    --configure-only) configure_only=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v jq >/dev/null 2>&1 || {
  printf 'Required executable not found: jq\n' >&2
  exit 1
}

if [[ -e "$config_file" && ! -f "$config_file" ]]; then
  printf 'Configuration is not a regular file: %s\n' "$config_file" >&2
  exit 1
fi
if [[ -f "$config_file" ]] && ! jq -e '
  type == "object" and (.remote_password? == null)
' "$config_file" >/dev/null; then
  printf 'Configuration is invalid or contains a password: %s\n' \
    "$config_file" >&2
  exit 1
fi

read_string() {
  local key=$1
  [[ -r "$config_file" ]] || return 0
  jq -er --arg key "$key" \
    '.[$key] | select(type == "string" and length > 0)' \
    "$config_file" 2>/dev/null || true
}

read_network() {
  local key=$1
  [[ -r "$config_file" ]] || return 0
  jq -er --arg key "$key" \
    '.[$key] | select(type == "array" and length > 0) | .[0]
     | select(type == "string" and length > 0)' \
    "$config_file" 2>/dev/null || true
}

read_number() {
  local key=$1
  [[ -r "$config_file" ]] || return 0
  jq -er --arg key "$key" \
    '.[$key] | select(type == "number" and floor == .)' \
    "$config_file" 2>/dev/null || true
}

remote_host=${remote_host:-$(read_string remote_host)}
remote_username=${remote_username:-$(read_string remote_username)}
sr_iso_name=${sr_iso_name:-$(read_string sr_iso_name)}
sr_name=${sr_name:-$(read_string sr_name)}
network_name=${network_name:-$(read_network network_names)}
export_network_name=${export_network_name:-$(read_network export_network_names)}
template_name=${template_name:-$(read_string vm_name)}
memory_mb=${memory_mb:-$(read_number memory_mb)}
disk_size_mb=${disk_size_mb:-$(read_number disk_size_mb)}
memory_mb=${memory_mb:-4096}
disk_size_mb=${disk_size_mb:-20480}

prompt_setting() {
  local variable_name=$1 label=$2 default_value=$3 current answer
  current=${!variable_name}
  [[ -n "$current" ]] && return
  [[ -t 0 ]] || {
    printf 'Missing %s; supply its option or run interactively.\n' "$label" >&2
    exit 1
  }
  read -r -p "$label [$default_value]: " answer
  printf -v "$variable_name" '%s' "${answer:-$default_value}"
}

prompt_setting remote_host "XCP-ng pool master" ""
prompt_setting remote_username "XCP-ng API username" root
prompt_setting sr_iso_name "ISO storage repository" "ISO library"
prompt_setting sr_name "Template disk storage repository" "Local storage"
prompt_setting network_name "DHCP-enabled build network" \
  "Network associated with eth0"
prompt_setting export_network_name "Template network" "$network_name"
prompt_setting template_name "Template name" Maestro

for value in \
  "$remote_host" \
  "$remote_username" \
  "$sr_iso_name" \
  "$sr_name" \
  "$network_name" \
  "$export_network_name" \
  "$template_name" \
  "$repo_url" \
  "$repo_branch"; do
  [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || {
    printf 'Configuration values must be non-empty single lines.\n' >&2
    exit 1
  }
done
[[ "$memory_mb" =~ ^[0-9]+$ && "$memory_mb" -ge 4096 ]] || {
  printf 'Memory must be an integer of at least 4096 MiB.\n' >&2
  exit 1
}
[[ "$disk_size_mb" =~ ^[0-9]+$ && "$disk_size_mb" -ge 20480 ]] || {
  printf 'Disk size must be an integer of at least 20480 MiB.\n' >&2
  exit 1
}
[[ -r "$operator_key" ]] || {
  printf 'Operator SSH public key not found: %s\n' "$operator_key" >&2
  exit 1
}
operator_key=$(realpath "$operator_key")

config_dir=$(dirname "$config_file")
[[ -d "$config_dir" ]] || {
  printf 'Configuration directory does not exist: %s\n' "$config_dir" >&2
  exit 1
}
config_dir=$(realpath "$config_dir")
config_file="$config_dir/$(basename "$config_file")"
config_tmp=$(mktemp "$config_dir/.maestro-pkrvars.XXXXXX")
cleanup() {
  rm -f -- "${config_tmp:-}"
}
trap cleanup EXIT HUP INT TERM
chmod 0600 "$config_tmp"
jq -n \
  --arg remote_host "$remote_host" \
  --arg remote_username "$remote_username" \
  --arg sr_iso_name "$sr_iso_name" \
  --arg sr_name "$sr_name" \
  --arg network_name "$network_name" \
  --arg export_network_name "$export_network_name" \
  --arg template_name "$template_name" \
  --arg repo_url "$repo_url" \
  --arg repo_branch "$repo_branch" \
  --argjson memory_mb "$memory_mb" \
  --argjson disk_size_mb "$disk_size_mb" \
  '{
    remote_host: $remote_host,
    remote_username: $remote_username,
    sr_iso_name: $sr_iso_name,
    sr_name: $sr_name,
    network_names: [$network_name],
    export_network_names: [$export_network_name],
    vm_name: $template_name,
    memory_mb: $memory_mb,
    disk_size_mb: $disk_size_mb,
    repo_url: $repo_url,
    repo_branch: $repo_branch
  }' >"$config_tmp"
mv -f "$config_tmp" "$config_file"
config_tmp=
printf 'Saved non-secret XCP-ng settings to %s\n' "$config_file"

[[ "$configure_only" -eq 0 ]] || exit 0

remote_password=${PKR_VAR_remote_password:-${XCP_HOSTPASSWORD:-}}
if [[ -z "$remote_password" && -n ${XCP_PASSWORD_PASS_ENTRY:-} ]]; then
  command -v pass >/dev/null || { echo 'Password-store provider is unavailable.' >&2; exit 1; }
  # Resolve SecretOps credentials only after configuration/Nix work is done.
  remote_password=$(pass show "$XCP_PASSWORD_PASS_ENTRY")
  remote_password=${remote_password%%$'\n'*}
fi
if [[ -z "$remote_password" ]]; then
  [[ -t 0 ]] || {
    printf 'Set PKR_VAR_remote_password for non-interactive deployment.\n' >&2
    exit 1
  }
  read -r -s -p "XCP-ng password for $remote_username: " remote_password
  printf '\n' >&2
fi
[[ -n "$remote_password" ]] || {
  printf 'The XCP-ng password must not be empty.\n' >&2
  exit 1
}

printf 'Deploying native XCP-ng template %s\n' "$template_name"
build_template=${MAESTRO_BUILD_TEMPLATE_BIN:-}
if [[ -z "$build_template" ]]; then
  if command -v maestro-build-template >/dev/null 2>&1; then
    build_template=maestro-build-template
  else
    build_template=$SCRIPT_DIR/build.sh
  fi
fi
REPO_URL="$repo_url" \
REPO_BRANCH="$repo_branch" \
PKR_VAR_remote_password="$remote_password" \
OPERATOR_PUBLIC_KEY_FILE="$operator_key" \
MAESTRO_SYSTEM_ROOT="$REPO_ROOT" \
MAESTRO_PACKER_ROOT="$PACKER_ROOT" \
  "$build_template" -var-file="$config_file"
