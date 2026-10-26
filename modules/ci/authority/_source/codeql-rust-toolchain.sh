#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${MAESTRO_CODEQL_RUST_TOOLCHAIN:?}" "${MAESTRO_CODEQL_RUSTUP:?}" "${MAESTRO_CODEQL_RUST_SRC:?}"
: "${RUNNER_TEMP:?}" "${GITHUB_PATH:?}" "${GITHUB_ENV:?}"
for value in "$MAESTRO_CODEQL_RUST_TOOLCHAIN" "$MAESTRO_CODEQL_RUSTUP" "$MAESTRO_CODEQL_RUST_SRC"; do
  [[ $value == /nix/store/* && $value != *$'\n'* && $value != *$'\r'* ]] || {
    echo 'CodeQL Rust tools must come from the pinned Nix store.' >&2
    exit 2
  }
done
[[ -x $MAESTRO_CODEQL_RUSTUP && -x $MAESTRO_CODEQL_RUST_TOOLCHAIN/bin/cargo &&
   -x $MAESTRO_CODEQL_RUST_TOOLCHAIN/bin/rustc && -x $MAESTRO_CODEQL_RUST_TOOLCHAIN/bin/rustdoc &&
   -f $MAESTRO_CODEQL_RUST_SRC/core/src/lib.rs ]] || {
  echo 'The pinned CodeQL Rust toolchain is incomplete.' >&2
  exit 2
}
[[ -f $GITHUB_PATH && -w $GITHUB_PATH && ! -L $GITHUB_PATH &&
   -f $GITHUB_ENV && -w $GITHUB_ENV && ! -L $GITHUB_ENV ]] || {
  echo 'Writable GitHub environment and path files are required.' >&2
  exit 2
}

state=$(mktemp -d "$RUNNER_TEMP/maestro-codeql-rust.XXXXXX")
export RUSTUP_HOME="$state/rustup" CARGO_HOME="$state/cargo"
export RUSTUP_TOOLCHAIN=maestro-nix RUSTUP_AUTO_INSTALL=0
export RUST_SRC_PATH="$MAESTRO_CODEQL_RUST_SRC"
export RUSTC="$MAESTRO_CODEQL_RUST_TOOLCHAIN/bin/rustc"
export RUSTDOC="$MAESTRO_CODEQL_RUST_TOOLCHAIN/bin/rustdoc"
mkdir -p "$state/bin" "$CARGO_HOME"
for tool in rustup cargo rustc rustdoc; do
  ln -s "$MAESTRO_CODEQL_RUSTUP" "$state/bin/$tool"
done
"$MAESTRO_CODEQL_RUSTUP" toolchain link maestro-nix "$MAESTRO_CODEQL_RUST_TOOLCHAIN"
export PATH="$state/bin:$PATH"
for tool in cargo rustc rustdoc; do
  resolved=$("$MAESTRO_CODEQL_RUSTUP" which --toolchain maestro-nix "$tool")
  [[ $(readlink -f "$resolved") == $(readlink -f "$MAESTRO_CODEQL_RUST_TOOLCHAIN/bin/$tool") ]] || {
    echo 'Rustup resolved a tool outside the pinned native toolchain.' >&2
    exit 2
  }
done
cargo --version
rustc --version
sysroot=$(rustc --print sysroot)
[[ $sysroot == /nix/store/* && -d $sysroot/lib/rustlib ]] || {
  echo 'CodeQL Rust resolved a compiler outside the pinned native toolchain.' >&2
  exit 2
}
printf '%s\n' "$state/bin" >>"$GITHUB_PATH"
for variable in RUSTUP_HOME CARGO_HOME RUSTUP_TOOLCHAIN RUSTUP_AUTO_INSTALL RUST_SRC_PATH RUSTC RUSTDOC; do
  value=${!variable}
  [[ $value != *$'\n'* && $value != *$'\r'* ]] || exit 2
  printf '%s=%s\n' "$variable" "$value" >>"$GITHUB_ENV"
done
