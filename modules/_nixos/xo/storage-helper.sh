#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${MAESTRO_XO_MOUNTS_DIR:?MAESTRO_XO_MOUNTS_DIR must be set}"
: "${MAESTRO_XO_DATA_DIR:?MAESTRO_XO_DATA_DIR must be set}"
: "${MAESTRO_XO_TEMP_DIR:?MAESTRO_XO_TEMP_DIR must be set}"
: "${MAESTRO_XO_USER:?MAESTRO_XO_USER must be set}"
: "${MAESTRO_XO_CREDENTIALS_DIR:?MAESTRO_XO_CREDENTIALS_DIR must be set}"
: "${MAESTRO_XO_ALLOWED_MOUNT_TYPES:=}"
: "${MAESTRO_XO_ENABLE_CIFS:=false}"
: "${MAESTRO_XO_ENABLE_VHD:=false}"

mounts_dir="$(realpath -m -- "$MAESTRO_XO_MOUNTS_DIR")"
data_dir="$(realpath -m -- "$MAESTRO_XO_DATA_DIR")"
temp_dir="$(realpath -m -- "$MAESTRO_XO_TEMP_DIR")"
credentials_dir="$MAESTRO_XO_CREDENTIALS_DIR"
credentials_file=""

fail() {
  echo "xo-storage-helper: $*" >&2
  exit 1
}

canonical_path() {
  case "${1:-}" in
    /*) realpath -m -- "$1" ;;
    *) fail "path must be absolute: ${1:-<missing>}" ;;
  esac
}

is_under() {
  case "$2" in
    "$1"|"$1"/*) return 0 ;;
    *) return 1 ;;
  esac
}

validate_mount_target() {
  local path
  path="$(canonical_path "${1:-}")"
  is_under "$mounts_dir" "$path" \
    || fail "mount target must be under $mounts_dir: $path"
}

validate_runtime_path() {
  local path
  path="$(canonical_path "${1:-}")"
  is_under "$mounts_dir" "$path" \
    || is_under "$data_dir" "$path" \
    || is_under "$temp_dir" "$path" \
    || fail "path is outside XO runtime storage: $path"
}

reject_cifs_secrets() {
  local option key
  local -a parsed_options=()
  IFS=, read -r -a parsed_options <<< "${1:-}"
  for option in "${parsed_options[@]}"; do
    key="${option%%=*}"
    key="${key,,}"
    case "$key" in
      user|username|pass|password|password2|cred|credentials)
        fail "CIFS credentials are not allowed in mount arguments"
        ;;
    esac
  done
}

validate_mount_options() {
  local option key
  local -a parsed=()
  IFS=, read -r -a parsed <<<"${1:-}"
  for option in "${parsed[@]}"; do
    key=${option%%=*}
    case "$key" in
      rw|ro|soft|hard|softerr|softreval|tcp|udp|sync|async|nosuid|nodev|noexec|relatime|noatime|nodiratime|nolock|lock|intr|nointr|noauto|_netdev|nofail|nounix|noperm|serverino|noserverino|seal|guest|multiuser|cache|vers|nfsvers|minorversion|proto|port|mountport|mountproto|timeo|retrans|rsize|wsize|actimeo|acregmin|acregmax|acdirmin|acdirmax|sec|domain|uid|gid|file_mode|dir_mode|iocharset|addr|clientaddr) ;;
      *) fail "mount option is not allowed: $key" ;;
    esac
    [[ $option != *$'\n'* && $option != *$'\r'* ]] || fail 'invalid mount option'
  done
}

require_mount_type() {
  case " $MAESTRO_XO_ALLOWED_MOUNT_TYPES " in
    *" $1 "*) ;;
    *) fail "filesystem type is not enabled: ${1:-<unset>}" ;;
  esac
}

run_mount() {
  local fstype="" options=""
  local -a args=() positional=()
  local saw_options=false saw_type=false

  while [ "$#" -gt 0 ]; do
    case "$1" in
      -t|--types)
        [ "$#" -ge 2 ] || fail "$1 requires an argument"
        [[ $saw_type == false ]] || fail 'repeated filesystem selector'
        saw_type=true
        fstype="$2"
        args+=("$1" "$2")
        shift 2
        ;;
      -o|--options)
        [ "$#" -ge 2 ] || fail "$1 requires an argument"
        [[ $saw_options == false ]] || fail 'repeated mount options'
        saw_options=true
        options="$2"
        shift 2
        ;;
      -*) fail "mount flag is not allowed: $1" ;;
      *)
        positional+=("$1")
        args+=("$1")
        shift
        ;;
    esac
  done

  [ "${#positional[@]}" -eq 2 ] || fail "mount requires exactly one source and target"
  validate_mount_target "${positional[$((${#positional[@]} - 1))]}"
  require_mount_type "$fstype"
  validate_mount_options "$options"
  [ "$fstype" != cifs ] || reject_cifs_secrets "$options"
  if { [ "$fstype" = nfs ] || [ "$fstype" = nfs4 ]; } && [ -z "$options" ]; then
    options=rw,soft,timeo=600,retrans=2
  fi
  options="${options:+$options,}nosuid,nodev"
  if [ -n "$options" ]; then
    exec mount -o "$options" "${args[@]}"
  fi
  exec mount "${args[@]}"
}

run_cifs() {
  local options=""
  local -a args=() positional=()
  local saw_options=false saw_type=false

  while [ "$#" -gt 0 ]; do
    case "$1" in
      -t|--types)
        [ "$#" -ge 2 ] && [ "$2" = cifs ] || fail "CIFS mount requires -t cifs"
        [[ $saw_type == false ]] || fail 'repeated filesystem selector'
        saw_type=true
        args+=("$1" "$2")
        shift 2
        ;;
      -o|--options)
        [ "$#" -ge 2 ] || fail "$1 requires an argument"
        [[ $saw_options == false ]] || fail 'repeated mount options'
        saw_options=true
        options="$2"
        shift 2
        ;;
      -*) fail "mount flag is not allowed: $1" ;;
      *)
        positional+=("$1")
        args+=("$1")
        shift
        ;;
    esac
  done

  [ "${#positional[@]}" -eq 2 ] || fail "mount requires exactly one source and target"
  validate_mount_target "${positional[$((${#positional[@]} - 1))]}"
  [[ $saw_type == true ]] || fail 'CIFS mount requires -t cifs'
  validate_mount_options "$options"
  reject_cifs_secrets "$options"

  local username="" password=""
  IFS= read -r username || fail "missing CIFS username"
  IFS= read -r password || fail "missing CIFS password"
  [ -n "$username" ] || fail "missing CIFS username"

  install -d -m 0700 -o root -g root "$credentials_dir"
  credentials_file="$(mktemp "$credentials_dir/credentials.XXXXXX")"
  trap 'rm -f -- "${credentials_file:-}"' EXIT
  chmod 0600 "$credentials_file"
  printf 'username=%s\npassword=%s\n' "$username" "$password" > "$credentials_file"

  local credential_options
  credential_options="nosuid,nodev,credentials=$credentials_file,uid=$(id -u "$MAESTRO_XO_USER"),gid=$(id -g "$MAESTRO_XO_USER")"
  if [ -n "$options" ]; then
    options="$options,$credential_options"
  else
    options="$credential_options"
  fi
  mount -o "$options" "${args[@]}"
}

run_target_command() {
  local command=$1 target='' output=''
  shift
  local -a args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -T|--target|-M|--mountpoint)
        [[ $# -ge 2 && -z $target ]] || fail 'one mount target is required'
        target=$2
        args+=("$1" "$2")
        shift 2
        ;;
      -o|--output)
        [[ $command == findmnt && $# -ge 2 && -z $output ]] || fail 'invalid findmnt output selector'
        output=$2
        [[ $output =~ ^(SOURCE|TARGET|FSTYPE|OPTIONS)(,(SOURCE|TARGET|FSTYPE|OPTIONS))*$ ]] || fail 'unsupported findmnt columns'
        args+=("$1" "$2")
        shift 2
        ;;
      -n|--noheadings|-r|--raw)
        [[ $command == findmnt ]] || fail 'invalid unmount flag'
        args+=("$1"); shift ;;
      -f|--force|-l|--lazy)
        [[ $command == umount ]] || fail 'invalid findmnt flag'
        args+=("$1"); shift ;;
      /*)
        [[ -z $target ]] || fail 'extra mount target'
        target=$1
        args+=("$1"); shift ;;
      *) fail "flag or operand is not allowed: $1" ;;
    esac
  done
  [[ -n $target ]] || fail "$command requires a target under $mounts_dir"
  validate_mount_target "$target"
  exec "$command" "${args[@]}"
}

run_vhdi() {
  local command="$1"
  shift
  local -a args=() positional=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -*) args+=("$1"); shift ;;
      *) positional+=("$1"); args+=("$1"); shift ;;
    esac
  done
  if [ "$command" = vhdimount ]; then
    [ "${#positional[@]}" -ge 2 ] || fail "vhdimount requires image and target"
    validate_runtime_path "${positional[$((${#positional[@]} - 2))]}"
    validate_mount_target "${positional[$((${#positional[@]} - 1))]}"
  else
    [ "${#positional[@]}" -ge 1 ] || fail "vhdiinfo requires an image"
    validate_runtime_path "${positional[$((${#positional[@]} - 1))]}"
  fi
  exec "$command" "${args[@]}"
}

[ "$#" -ge 1 ] || fail "missing command"
command="$1"
shift
case "$command" in
  mount) run_mount "$@" ;;
  mount-cifs-with-credentials)
    [ "$MAESTRO_XO_ENABLE_CIFS" = true ] || fail "CIFS support is disabled"
    run_cifs "$@"
    ;;
  umount|findmnt) run_target_command "$command" "$@" ;;
  vhdimount|vhdiinfo)
    [ "$MAESTRO_XO_ENABLE_VHD" = true ] || fail "VHD support is disabled"
    run_vhdi "$command" "$@"
    ;;
  *) fail "command is not allowed: $command" ;;
esac
