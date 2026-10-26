#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_SECURITY_INVENTORY_SOURCE:?}"
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
flake_ref="path:$repo_root"
if git -C "$repo_root" rev-parse --show-toplevel >/dev/null 2>&1; then
  flake_ref="git+file:$repo_root?shallow=1"
fi
# Exercise the same CLI and decoder used for enrichment before building media.
# The verdict derivation is inexpensive and includes structured shell attributes.
drv=$(nix eval --accept-flake-config --no-write-lock-file --raw \
  "$flake_ref#packages.x86_64-linux.maestro-ci-verdict.drvPath")
nix --version
python3 - "$MAESTRO_SECURITY_INVENTORY_SOURCE" "$drv" <<'PYTHON'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("inventory", sys.argv[1])
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
records = inventory.read_derivations([sys.argv[2]])
for record in records.values():
    inventory.patches(record)
    for output, info in record["outputs"].items():
        if not inventory.output_path(record, output, info):
            raise ValueError("missing preflight derivation output identity")
print("Hosted derivation JSON inventory preflight passed")
PYTHON
