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

PACKER_BIN=${PACKER_BIN:-packer-xenserver}
NIX_BIN=${NIX_BIN:-nix}
GH_BIN=${GH_BIN:-gh}
JQ_BIN=${JQ_BIN:-jq}
OPERATOR_PUBLIC_KEY_FILE=${OPERATOR_PUBLIC_KEY_FILE:-${HOME:-}/.ssh/id_ed25519.pub}
INSTALLER_ISO=${INSTALLER_ISO:-}
INSTALLER_SOURCE=${INSTALLER_SOURCE:-github}
GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-closure-labs/maestro}
export GITHUB_REPOSITORY
REPO_URL=${REPO_URL:-https://github.com/closure-labs/maestro.git}
REPO_BRANCH=${REPO_BRANCH:-main}
REPO_REVISION=${REPO_REVISION:-}

if [[ ${BUILD_INSTALLER+x} ]]; then
  case "$BUILD_INSTALLER" in
    0) INSTALLER_SOURCE=local ;;
    1) INSTALLER_SOURCE=build ;;
    *)
      printf 'BUILD_INSTALLER must be 1 or 0.\n' >&2
      exit 1
      ;;
  esac
fi
if [[ -n "$INSTALLER_ISO" ]]; then
  INSTALLER_SOURCE=local
fi

case "$INSTALLER_SOURCE" in
  github|build|local) ;;
  *)
    printf 'INSTALLER_SOURCE must be github, build, or local.\n' >&2
    exit 1
    ;;
esac

command -v "$PACKER_BIN" >/dev/null 2>&1 || {
  printf 'Packer executable not found: %s\n' "$PACKER_BIN" >&2
  exit 1
}
[[ -r "$OPERATOR_PUBLIC_KEY_FILE" ]] || {
  printf 'Operator SSH public key not found: %s\n' \
    "$OPERATOR_PUBLIC_KEY_FILE" >&2
  exit 1
}

artifact_dir=
cleanup() {
  [[ -z "$artifact_dir" ]] || rm -rf -- "$artifact_dir"
  [[ -z ${bootstrap_dir:-} ]] || rm -rf -- "$bootstrap_dir"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$INSTALLER_SOURCE" in
  github)
    command -v "$GH_BIN" >/dev/null 2>&1 || {
      printf 'GitHub CLI executable not found: %s\n' "$GH_BIN" >&2
      exit 1
    }
    artifact_dir=$(mktemp -d "${TMPDIR:-/tmp}/maestro-installer.XXXXXX")
    rmdir "$artifact_dir"
    GH_BIN="$GH_BIN" maestro-ci-download-installer "$artifact_dir"
    installer_iso="$artifact_dir/result-installer/iso/maestro-installer.iso"
    qualified_revision=$("$JQ_BIN" -er .source_commit "$artifact_dir/selected-state.json")
    [[ -z "$REPO_REVISION" || $REPO_REVISION == "$qualified_revision" ]] || {
      echo 'Requested revision differs from qualified installer state.' >&2; exit 1;
    }
    [[ $REPO_URL == "https://github.com/$GITHUB_REPOSITORY.git" ]] || {
      echo 'Qualified installer repository differs from installation repository.' >&2; exit 1;
    }
    REPO_REVISION=$qualified_revision
    ;;
  build)
    command -v "$NIX_BIN" >/dev/null 2>&1 || {
      printf 'Nix executable not found: %s\n' "$NIX_BIN" >&2
      exit 1
    }
    installer_result=$(
      "$NIX_BIN" build \
        "path:$REPO_ROOT#installer-iso" \
        --accept-flake-config \
        --no-link \
        --print-out-paths
    )
    [[ -n "$installer_result" && "$installer_result" != *$'\n'* ]] || {
      printf 'Nix returned an invalid installer output path.\n' >&2
      exit 1
    }
    installer_iso="$installer_result/iso/maestro-installer.iso"
    ;;
  local)
    installer_iso=${INSTALLER_ISO:-$REPO_ROOT/output/maestro-installer.iso}
    ;;
esac

# Resolve a moving branch once, before the VM can erase a disk.
if [[ -z "$REPO_REVISION" ]]; then
  REPO_REVISION=$(git ls-remote --exit-code "$REPO_URL" "refs/heads/$REPO_BRANCH" | awk '{print $1}')
fi
[[ $REPO_REVISION =~ ^[0-9a-f]{40}$ ]] || {
  echo 'Installation requires one immutable 40-character source revision.' >&2; exit 1;
}

bootstrap_dir=$(mktemp -d "${TMPDIR:-/tmp}/maestro-bootstrap.XXXXXX")
chmod 0700 "$bootstrap_dir"
ssh-keygen -q -t ed25519 -N '' -C maestro-packer-bootstrap -f "$bootstrap_dir/key"
bootstrap_public_key_b64=$(base64 -w0 "$bootstrap_dir/key.pub")

[[ -s "$installer_iso" ]] || {
  printf 'Installer ISO does not exist or is empty: %s\n' "$installer_iso" >&2
  exit 1
}
installer_iso=$(realpath "$installer_iso")
installer_sha256=$(sha256sum "$installer_iso" | awk '{print $1}')
operator_key=$(realpath "$OPERATOR_PUBLIC_KEY_FILE")
printf 'Installer ISO: %s\n' "$installer_iso"

cd "$PACKER_ROOT"
"$PACKER_BIN" init .
"$PACKER_BIN" build \
  -parallel-builds=1 \
  "$@" \
  -var "iso_url=$installer_iso" \
  -var "iso_checksum=sha256:$installer_sha256" \
  -var "operator_public_key_file=$operator_key" \
  -var "bootstrap_private_key_file=$bootstrap_dir/key" \
  -var "bootstrap_public_key_b64=$bootstrap_public_key_b64" \
  -var "repo_revision=$REPO_REVISION" \
  -var "repo_url=$REPO_URL" \
  .
