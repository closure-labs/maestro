#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
codeql_command=${1:?packaged CodeQL Rust setup command is required}
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/host" "$work/runner"
for tool in cargo rustc rustdoc rustup; do
  cat >"$work/host/$tool" <<'SPOOF'
#!/usr/bin/env bash
echo 'The host Rust toolchain must never run.' >&2
exit 99
SPOOF
  chmod +x "$work/host/$tool"
done
: >"$work/environment"
: >"$work/path"
export RUNNER_TEMP="$work/runner" GITHUB_ENV="$work/environment" GITHUB_PATH="$work/path"
export PATH="$work/host:$PATH"
"$codeql_command"
# Parse GitHub's simple KEY=VALUE records as data, without sourcing a shell file.
while IFS='=' read -r name value; do
  case "$name" in
    RUSTUP_HOME|CARGO_HOME|RUSTUP_TOOLCHAIN|RUSTUP_AUTO_INSTALL|RUST_SRC_PATH|RUSTC|RUSTDOC)
      export "$name=$value" ;;
    *) echo 'Unexpected CodeQL toolchain environment record.' >&2; exit 1 ;;
  esac
done <"$GITHUB_ENV"
[[ $RUSTUP_HOME == "$RUNNER_TEMP/"* && $CARGO_HOME == "$RUNNER_TEMP/"* ]]
[[ $RUSTUP_TOOLCHAIN == maestro-nix && $RUSTUP_AUTO_INSTALL == 0 ]]
[[ $RUSTC == /nix/store/* && $RUSTDOC == /nix/store/* && $RUST_SRC_PATH == /nix/store/* ]]
IFS= read -r proxy_directory <"$GITHUB_PATH"
[[ $proxy_directory == "$RUNNER_TEMP/"*/bin ]]
export PATH="$proxy_directory:$PATH"
[[ $(readlink -f "$(rustup which cargo)") == /nix/store/* ]]
cargo --version
rustc --version
if rustup run deliberately-uninstalled-codeql-toolchain cargo --version; then
  echo 'An uninstalled toolchain must fail instead of downloading or using a host tool.' >&2
  exit 1
fi
