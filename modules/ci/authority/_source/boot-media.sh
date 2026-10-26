#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

iso=${1:?usage: boot-installer-iso.sh ISO}
[[ -s "$iso" ]] || {
  printf 'Installer ISO is missing: %s\n' "$iso" >&2
  exit 2
}

qemu_bin=${QEMU_BIN:-qemu-system-x86_64}
qemu_img_bin=${QEMU_IMG_BIN:-qemu-img}
boot_timeout=${BOOT_TIMEOUT:-5m}
# Flake-built media lives in the immutable store. Retain a writable, distinct
# log by default; hosted jobs may still select their artifact path explicitly.
log=${BOOT_LOG:-$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-qemu-boot.XXXXXX.log")}
printf 'Installer boot log: %s\n' "$log"
disk=$(mktemp "${TMPDIR:-/tmp}/maestro-boot.XXXXXX.qcow2")
trap 'rm -f -- "$disk"' EXIT

command -v "$qemu_bin" >/dev/null
command -v "$qemu_img_bin" >/dev/null
"$qemu_img_bin" create -q -f qcow2 "$disk" 24G

acceleration=(-accel "tcg,thread=multi")
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  acceleration=(-accel kvm)
fi

boot_pattern='maestro-installer login:|Reached target .*Multi-User System|Started OpenSSH'
: >"$log"

timeout --signal=TERM "$boot_timeout" \
  "$qemu_bin" \
    "${acceleration[@]}" \
    -machine q35 \
    -m 4096 \
    -smp 2 \
    -drive "file=${disk},if=virtio,format=qcow2" \
    -cdrom "$iso" \
    -boot d \
    -display none \
    -no-reboot \
    -chardev stdio,id=maestro-console,signal=off \
    -device virtio-serial-pci \
    -device virtconsole,chardev=maestro-console >"$log" 2>&1 &
qemu_pid=$!

reached_target=false
while kill -0 "$qemu_pid" 2>/dev/null; do
  if grep -Eqi "$boot_pattern" "$log"; then
    reached_target=true
    kill -TERM "$qemu_pid" 2>/dev/null || true
    break
  fi
  sleep 1
done

set +e
wait "$qemu_pid"
qemu_status=$?
set -e

if grep -Eqi "$boot_pattern" "$log"; then
  reached_target=true
fi

case "$qemu_status" in
  0|124|143) ;;
  *)
    printf 'QEMU failed with status %s\n' "$qemu_status" >&2
    exit "$qemu_status"
    ;;
esac

[[ "$reached_target" == true ]] || {
  cat "$log" >&2
  printf 'The ISO did not reach the Maestro installer login target.\n' >&2
  exit 1
}
