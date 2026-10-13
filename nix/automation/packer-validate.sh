#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
work=$(mktemp -d "${TMPDIR:-/tmp}/maestro-packer-validation.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
ssh-keygen -q -t ed25519 -N '' -C validation -f "$work/key"
printf 'validation ISO\n' >"$work/installer.iso"
jq -n --arg directory "$work" --arg public_key "$(base64 -w0 "$work/key.pub")" \
  --arg checksum "$(sha256sum "$work/installer.iso" | cut -d' ' -f1)" '{
    remote_host:"192.0.2.1",remote_username:"root",remote_password:"validation-only",
    sr_iso_name:"validation-iso",sr_name:"validation-storage",
    iso_url:($directory + "/installer.iso"),iso_checksum:("sha256:" + $checksum),
    operator_public_key_file:($directory + "/key.pub"),
    bootstrap_private_key_file:($directory + "/key"),bootstrap_public_key_b64:$public_key,
    repo_revision:("a"*40),network_names:["validation"],export_network_names:["validation"]
  }' >"$work/validation.pkrvars.json"
packer-xenserver fmt -check "$repo_root/packer"
packer-xenserver init "$repo_root/packer"
packer-xenserver validate -var-file="$work/validation.pkrvars.json" "$repo_root/packer"
