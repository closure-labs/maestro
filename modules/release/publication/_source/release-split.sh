#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

source_iso=${1:?usage: stage-release-installer.sh SOURCE_ISO VERSIONED_ISO RELEASE_DIR}
versioned_iso=${2:?usage: stage-release-installer.sh SOURCE_ISO VERSIONED_ISO RELEASE_DIR}
release_dir=${3:?usage: stage-release-installer.sh SOURCE_ISO VERSIONED_ISO RELEASE_DIR}
part_size=${MAESTRO_RELEASE_PART_SIZE:-1900M}
asset_limit=${MAESTRO_RELEASE_ASSET_LIMIT:-2147483648}

[[ -f "$source_iso" ]] || {
  printf 'Installer ISO does not exist: %s\n' "$source_iso" >&2
  exit 1
}
[[ ! -e "$versioned_iso" ]] || {
  printf 'Refusing to replace versioned installer: %s\n' "$versioned_iso" >&2
  exit 1
}

install -d -m 0755 "$(dirname "$versioned_iso")" "$release_dir"
ln "$source_iso" "$versioned_iso" 2>/dev/null \
  || cp --reflink=auto "$source_iso" "$versioned_iso"

asset_name=$(basename "$versioned_iso")
split \
  --bytes="$part_size" \
  --numeric-suffixes=1 \
  --suffix-length=2 \
  "$versioned_iso" \
  "$release_dir/${asset_name}.part-"

mapfile -t parts < <(find "$release_dir" -maxdepth 1 -type f \
  -name "${asset_name}.part-*" -print | sort)
[[ ${#parts[@]} -gt 0 ]]
for part in "${parts[@]}"; do
  part_bytes=$(stat --format=%s "$part")
  ((part_bytes < asset_limit)) || {
    printf 'Release part exceeds the asset limit: %s (%s bytes)\n' \
      "$part" "$part_bytes" >&2
    exit 1
  }
done

installer_sha256=$(sha256sum "$versioned_iso" | cut -d' ' -f1)
printf '%s  %s\n' "$installer_sha256" "$asset_name" \
  >"$release_dir/${asset_name}.sha256"
