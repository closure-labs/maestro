#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (($# != 1)) || [[ ! "$1" =~ ^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-xen-orchestra-ce-[A-Za-z0-9.+_-]+$ ]]; then
  echo 'Expected one immutable xen-orchestra-ce store path' >&2
  exit 2
fi

# Metadata alone does not prove that a cache still has its advertised NARs.
# Copy the entire closure without builders, preserving normal signature checks.
# An incomplete publication must not silently trigger upstream source rebuilds.
for cache in https://xen-orchestra-ce.cachix.org https://maestro.cachix.org; do
  if nix path-info --option narinfo-cache-negative-ttl 0 --option narinfo-cache-positive-ttl 0 --store "$cache" "$1"; then
    if nix copy --option narinfo-cache-negative-ttl 0 --option narinfo-cache-positive-ttl 0 --from "$cache" "$1"; then
      printf 'Locked XO closure was verified and substituted from %s\n' "$cache"
      exit 0
    fi
    printf 'Cache %s advertises the locked XO output but cannot supply its complete closure.\n' "$cache" >&2
  fi
done
echo 'Locked XO closure is not fully substitutable from either approved publication cache; repair or republish the admitted closure upstream before qualification.' >&2
exit 1
