#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

test_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT

fake_bin="$temporary/bin"
mkdir -p "$fake_bin" "$temporary/credentials"

cat >"$fake_bin/mount" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >"$FAKE_MOUNT_LOG"
options=
while (($# > 0)); do
  if [[ $1 == -o ]]; then
    options=$2
    shift 2
  else
    shift
  fi
done
case ",$options," in
  *,credentials=*,*)
    credentials=${options#*credentials=}
    credentials=${credentials%%,*}
    cp "$credentials" "$FAKE_CREDENTIALS_SNAPSHOT"
    ;;
esac
EOF

cat >"$fake_bin/id" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -u) printf '1001\n' ;;
  -g) printf '1002\n' ;;
  *) exit 2 ;;
esac
EOF

cat >"$fake_bin/install" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target=${!#}
mkdir -p "$target"
EOF

cat >"$fake_bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >"$FAKE_SUDO_LOG"
cat >"$FAKE_SUDO_STDIN"
EOF

sed -i "1c#!${BASH}" \
  "$fake_bin/mount" \
  "$fake_bin/id" \
  "$fake_bin/install" \
  "$fake_bin/sudo"
chmod +x "$fake_bin/mount" "$fake_bin/id" "$fake_bin/install" "$fake_bin/sudo"

helper="$test_root/modules/_nixos/xo/storage-helper.sh"
wrapper="$test_root/modules/_nixos/xo/sudo-wrapper.sh"
mount_log="$temporary/mount.log"
credentials_snapshot="$temporary/credentials.snapshot"

run_helper() {
  env \
    PATH="$fake_bin:$PATH" \
    FAKE_MOUNT_LOG="$mount_log" \
    FAKE_CREDENTIALS_SNAPSHOT="$credentials_snapshot" \
    MAESTRO_XO_MOUNTS_DIR=/var/lib/xo/mounts \
    MAESTRO_XO_DATA_DIR=/var/lib/xo/data \
    MAESTRO_XO_TEMP_DIR=/var/lib/xo/tmp \
    MAESTRO_XO_USER=xo \
    MAESTRO_XO_CREDENTIALS_DIR="$temporary/credentials" \
    MAESTRO_XO_ALLOWED_MOUNT_TYPES='cifs nfs nfs4' \
    MAESTRO_XO_ENABLE_CIFS=true \
    MAESTRO_XO_ENABLE_VHD=true \
    bash "$helper" "$@"
}

run_helper mount -t nfs server:/export /var/lib/xo/mounts/test
grep -Fq 'rw,soft,timeo=600,retrans=2' "$mount_log"

if run_helper mount -t nfs server:/export /etc >/dev/null 2>&1; then
  printf 'storage helper accepted a mount target outside its root\n' >&2
  exit 1
fi

if run_helper mount -t ext4 /dev/test /var/lib/xo/mounts/test >/dev/null 2>&1; then
  printf 'storage helper accepted a disabled filesystem type\n' >&2
  exit 1
fi

if run_helper mount -t cifs -o username=leak //server/share /var/lib/xo/mounts/test \
  >/dev/null 2>&1; then
  printf 'storage helper accepted CIFS credentials in arguments\n' >&2
  exit 1
fi

printf 'operator\nsecret\n' \
  | run_helper mount-cifs-with-credentials -t cifs //server/share /var/lib/xo/mounts/test
grep -Fxq 'username=operator' "$credentials_snapshot"
grep -Fxq 'password=secret' "$credentials_snapshot"
if find "$temporary/credentials" -type f -print -quit | grep -q .; then
  printf 'storage helper retained a temporary CIFS credential file\n' >&2
  exit 1
fi

if env \
  PATH="$fake_bin:$PATH" \
  MAESTRO_XO_MOUNTS_DIR=/var/lib/xo/mounts \
  MAESTRO_XO_DATA_DIR=/var/lib/xo/data \
  MAESTRO_XO_TEMP_DIR=/var/lib/xo/tmp \
  MAESTRO_XO_USER=xo \
  MAESTRO_XO_CREDENTIALS_DIR="$temporary/credentials" \
  MAESTRO_XO_ENABLE_CIFS=false \
  MAESTRO_XO_ENABLE_VHD=false \
  bash "$helper" mount-cifs-with-credentials -t cifs //server/share /var/lib/xo/mounts/test \
  >/dev/null 2>&1; then
  printf 'storage helper allowed disabled CIFS support\n' >&2
  exit 1
fi

if env \
  PATH="$fake_bin:$PATH" \
  MAESTRO_XO_MOUNTS_DIR=/var/lib/xo/mounts \
  MAESTRO_XO_DATA_DIR=/var/lib/xo/data \
  MAESTRO_XO_TEMP_DIR=/var/lib/xo/tmp \
  MAESTRO_XO_USER=xo \
  MAESTRO_XO_CREDENTIALS_DIR="$temporary/credentials" \
  MAESTRO_XO_ENABLE_CIFS=false \
  MAESTRO_XO_ENABLE_VHD=false \
  bash "$helper" vhdiinfo /var/lib/xo/data/disk.vhd \
  >/dev/null 2>&1; then
  printf 'storage helper allowed disabled VHD support\n' >&2
  exit 1
fi

sudo_log="$temporary/sudo.log"
sudo_stdin="$temporary/sudo.stdin"
printf 'operator\nsecret\n' \
  | env \
    PATH="$fake_bin:$PATH" \
    FAKE_SUDO_LOG="$sudo_log" \
    FAKE_SUDO_STDIN="$sudo_stdin" \
    MAESTRO_XO_STORAGE_HELPER=/nix/store/test/bin/xo-storage-helper \
    MAESTRO_XO_SUDO="$fake_bin/sudo" \
    USER=operator \
    PASSWD=secret \
    bash "$wrapper" -n mount -t cifs //server/share /var/lib/xo/mounts/test
grep -Fq -- '-n /nix/store/test/bin/xo-storage-helper mount-cifs-with-credentials' "$sudo_log"
grep -Fxq 'operator' "$sudo_stdin"
grep -Fxq 'secret' "$sudo_stdin"

# Unknown flags, alternate mount modes, repeated selectors, and extra operands
# must never reach a privileged binary.
for arguments in \
  'mount --bind -t nfs server:/export /var/lib/xo/mounts/test' \
  'mount -t nfs -t nfs4 server:/export /var/lib/xo/mounts/test' \
  'mount -t nfs -o rw -o ro server:/export /var/lib/xo/mounts/test' \
  'mount -t nfs -o remount server:/export /var/lib/xo/mounts/test' \
  'mount -t nfs server:/export /etc /var/lib/xo/mounts/test' \
  'umount -a /var/lib/xo/mounts/test' \
  'findmnt --tab-file /etc/passwd -T /var/lib/xo/mounts/test'; do
  read -r -a parsed <<<"$arguments"
  if run_helper "${parsed[@]}" >/dev/null 2>&1; then
    echo "Storage helper accepted unsafe arguments: $arguments" >&2
    exit 1
  fi
done
