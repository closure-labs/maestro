#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (($# != 1)) || [[ ! "$1" =~ ^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-xen-orchestra-ce-[A-Za-z0-9.+_-]+$ ]]; then
  echo 'Expected one immutable xen-orchestra-ce store path' >&2
  exit 2
fi

# Availability is independent of the upstream supply assertion. Actual
# realisation still verifies signatures using the flake's reviewed trust keys.
for cache in https://xen-orchestra-ce.cachix.org https://maestro.cachix.org; do
  if nix path-info --option narinfo-cache-negative-ttl 0 --option narinfo-cache-positive-ttl 0 --store "$cache" "$1"; then
    printf 'Locked XO output is available from %s\n' "$cache"
    exit 0
  fi
done
echo 'Locked XO output is absent from both approved publication caches' >&2
exit 1
