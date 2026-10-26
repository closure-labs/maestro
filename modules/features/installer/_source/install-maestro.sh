#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly INSTALL_ROOT=/mnt
readonly DEFAULT_REPO_URL=https://github.com/closure-labs/maestro.git
readonly DEFAULT_BRANCH=main

usage() {
  cat <<'EOF'
Usage: install-maestro [options]

Destructively install Maestro on the single writable disk in this VM.

Options:
  --disk DEVICE        target disk; auto-detected when exactly one exists
  --repo-url URL       Maestro repository URL
  --branch NAME        repository branch to install
  --revision SHA       immutable repository commit (required)
  --operator-key FILE  required SSH public key file for maestro
  --bootstrap-key FILE temporary Packer public key, removed at sealing
  --timezone ZONE      appliance timezone
  --git-name NAME      operator Git author name
  --git-email EMAIL    operator Git author email
  --yes                confirm destructive installation
  -h, --help           show this help
EOF
}

die() {
  printf 'install-maestro: %s\n' "$1" >&2
  exit 1
}

require_argument() {
  [[ "$#" -ge 2 && -n "$2" ]] || die "$1 requires a value"
}

target_disk=
repo_url=$DEFAULT_REPO_URL
branch=$DEFAULT_BRANCH
operator_key_file=
bootstrap_key_file=
revision=
timezone=America/Chicago
git_name="Maestro Admin"
git_email=maestro@maestro
confirmed=0

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --disk)
      require_argument "$@"
      target_disk=$2
      shift 2
      ;;
    --repo-url)
      require_argument "$@"
      repo_url=$2
      shift 2
      ;;
    --branch)
      require_argument "$@"
      branch=$2
      shift 2
      ;;
    --operator-key)
      require_argument "$@"
      operator_key_file=$2
      shift 2
      ;;
    --bootstrap-key)
      require_argument "$@"
      bootstrap_key_file=$2
      shift 2
      ;;
    --revision)
      require_argument "$@"
      revision=$2
      shift 2
      ;;
    --timezone)
      require_argument "$@"
      timezone=$2
      shift 2
      ;;
    --git-name)
      require_argument "$@"
      git_name=$2
      shift 2
      ;;
    --git-email)
      require_argument "$@"
      git_email=$2
      shift 2
      ;;
    --yes)
      confirmed=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "must run as root"
[[ "$confirmed" -eq 1 ]] || die "refusing to erase a disk without --yes"
[[ -r "$operator_key_file" ]] || die "operator public key is required"
[[ $revision =~ ^[0-9a-f]{40}$ ]] || die "--revision requires an immutable full commit SHA"

mapfile -t operator_keys < <(
  sed -nE '/^(ssh-|ecdsa-|sk-)[^[:space:]]+[[:space:]]+[^[:space:]]+/p' \
    "$operator_key_file"
)
[[ "${#operator_keys[@]}" -eq 1 ]] \
  || die "operator key file must contain exactly one valid public key"
ssh-keygen -l -f "$operator_key_file" >/dev/null || die "operator key is invalid"
bootstrap_key=
if [[ -n $bootstrap_key_file ]]; then
  [[ -f $bootstrap_key_file && ! -L $bootstrap_key_file ]] || die "bootstrap key must be a regular file"
  ssh-keygen -l -f "$bootstrap_key_file" >/dev/null || die "bootstrap key is invalid"
  bootstrap_key=$(awk 'NF >= 2 {print $1 " " $2}' "$bootstrap_key_file")
  [[ $bootstrap_key =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+$ ]] || die "bootstrap key must be one Ed25519 key"
fi

if [[ -z "$target_disk" ]]; then
  mapfile -t install_disks < <(
    lsblk -dnpo NAME,TYPE,RO,RM |
      awk '$2 == "disk" && $3 == 0 && $4 == 0 { print $1 }'
  )
  [[ "${#install_disks[@]}" -eq 1 ]] \
    || die "expected one writable non-removable disk; pass --disk explicitly"
  target_disk=${install_disks[0]}
fi

[[ -b "$target_disk" ]] || die "target is not a block device: $target_disk"
[[ "$(lsblk -dnro TYPE "$target_disk")" == disk ]] \
  || die "target is not a whole disk: $target_disk"
[[ "$(lsblk -dnro RO "$target_disk")" == 0 ]] \
  || die "target disk is read-only: $target_disk"

case "$target_disk" in
  *[0-9])
    efi_partition="${target_disk}p1"
    root_partition="${target_disk}p2"
    ;;
  *)
    efi_partition="${target_disk}1"
    root_partition="${target_disk}2"
    ;;
esac

# Fetch and validate source before any destructive disk operation.
source_checkout=$(mktemp -d "${TMPDIR:-/tmp}/maestro-source.XXXXXX")
packer_module_tmp=
cleanup() {
  [[ -z $source_checkout ]] || rm -rf -- "$source_checkout"
  [[ -z $packer_module_tmp ]] || rm -f -- "$packer_module_tmp"
}
trap cleanup EXIT
git clone --branch "$branch" --single-branch "$repo_url" "$source_checkout"
git -C "$source_checkout" fetch --no-tags origin "$revision"
git -C "$source_checkout" checkout --detach "$revision"
[[ $(git -C "$source_checkout" rev-parse HEAD) == "$revision" ]] || die "source revision verification failed"

printf 'Installing Maestro from %s (%s) onto %s\n' \
  "$repo_url" "$branch" "$target_disk"

wipefs --all --force "$target_disk"
sgdisk --zap-all "$target_disk"
sgdisk \
  --new=1:1MiB:+1GiB \
  --typecode=1:ef00 \
  --change-name=1:ESP \
  --new=2:0:0 \
  --typecode=2:8300 \
  --change-name=2:nixos \
  "$target_disk"
partprobe "$target_disk"
udevadm settle

mkfs.fat -F 32 -n ESP "$efi_partition"
mkfs.ext4 -F -L nixos "$root_partition"

sync
udevadm settle --timeout=30
mount_attempt=1
until mount -t ext4 "$root_partition" "$INSTALL_ROOT"; do
  if [[ "$mount_attempt" -ge 10 ]]; then
    printf 'Unable to mount the new root filesystem after %s attempts.\n' \
      "$mount_attempt" >&2
    lsblk -f "$target_disk" >&2 || true
    blkid -p "$root_partition" >&2 || true
    dumpe2fs -h "$root_partition" >&2 || true
    (dmesg || true) | tail -100 >&2
    die "new root filesystem did not become mountable"
  fi
  sleep 1
  udevadm settle --timeout=30
  ((mount_attempt += 1))
done
install -d -m 0755 "$INSTALL_ROOT/boot"
mount -o fmask=0077,dmask=0077 "$efi_partition" "$INSTALL_ROOT/boot"

repo_dir="$INSTALL_ROOT/home/maestro/maestro"
install -d -m 0755 "$(dirname "$repo_dir")"
mv -- "$source_checkout" "$repo_dir"
source_checkout=

export MAESTRO_SYSTEM_ROOT="$repo_dir"
# The checkout does not exist on the live ISO when ShellCheck runs.
# shellcheck disable=SC1091
. "$repo_dir/modules/features/operator/cli/_source/lib/common.sh"

maestro_write_host_settings \
  "$MAESTRO_SETTINGS_FILE" \
  "/home/maestro/maestro" \
  "$timezone" \
  "26.05" \
  "$git_name" \
  "$git_email" \
  operator_keys

nixos-generate-config --root "$INSTALL_ROOT"
install -m 0644 \
  "$INSTALL_ROOT/etc/nixos/hardware-configuration.nix" \
  "$MAESTRO_HARDWARE_FILE"

# Preserve only the temporary public build key across the first reboot.
# The sealing provisioner restores the tracked empty module.
if [[ -n $bootstrap_key ]]; then
  packer_module_tmp="$(mktemp "$repo_dir/host/.packer.XXXXXX")"
  cat >"$packer_module_tmp" <<EOF
# SPDX-License-Identifier: Apache-2.0
{lib, ...}: {
  users.users.maestro.openssh.authorizedKeys.keys = lib.mkAfter [ "$bootstrap_key" ];
}
EOF
  chmod 0644 "$packer_module_tmp"
  mv -f "$packer_module_tmp" "$repo_dir/host/packer.nix"
packer_module_tmp=
fi

nixos-install \
  --root "$INSTALL_ROOT" \
  --flake "path:$repo_dir#maestro" \
  --no-root-passwd

chown -R 1000:100 "$INSTALL_ROOT/home/maestro"
sync
printf 'Maestro installation complete; rebooting into the installed system.\n'
systemctl reboot
