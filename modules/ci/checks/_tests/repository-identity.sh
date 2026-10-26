#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
TEST_ROOT=${MAESTRO_SYSTEM_ROOT:-$PWD}
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# The released changelog remains an immutable historical record. No active
# product or CLI identity may survive the clean-break rebrand.
old_product='nix''oa'
old_cli='nx''cli'
while IFS= read -r -d '' source_file; do
  relative_path=${source_file#"$TEST_ROOT"/}
  case "$relative_path" in
    docs/history/legacy-changelog.md | modules/features/operator/menu/_source/frontend/Cargo.lock)
      continue
      ;;
  esac
  if [[ ${relative_path,,} == *"$old_product"* || ${relative_path,,} == *"$old_cli"* ]]; then
    fail "legacy identity remains in active path: $relative_path"
  fi
  matches=$(grep -InEi "${old_product}|${old_cli}" "$source_file" || true)
  [[ -z $matches ]] || fail "legacy identity remains in $relative_path: $matches"
done < <(
  find "$TEST_ROOT" \
    \( -path "$TEST_ROOT/.git" -o -path "$TEST_ROOT/.jj" -o -path "$TEST_ROOT/.devenv" -o -path "$TEST_ROOT/modules/features/operator/menu/_source/frontend/target" \) -prune \
    -o -type f -print0
)

printf 'Repository identity contract passed.\n'
