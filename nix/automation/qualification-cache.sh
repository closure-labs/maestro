#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (($# != 1)) || [[ ! "$1" =~ ^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-xen-orchestra-ce-[A-Za-z0-9.+_-]+$ ]]; then
  echo 'Expected one immutable xen-orchestra-ce store path' >&2
  exit 2
fi

# Child commands do not inherit an outer `nix run --accept-flake-config`.
# Keep this exact public cache/key allowlist aligned with flake.nix. Application
# caches need not duplicate stock nixpkgs dependencies from cache.nixos.org.
caches=(https://cache.nixos.org https://xen-orchestra-ce.cachix.org https://maestro.cachix.org)
keys='cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E= maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0='
options=(--option narinfo-cache-negative-ttl 0 --option narinfo-cache-positive-ttl 0
  --option substituters "${caches[*]}" --option trusted-public-keys "$keys"
  --option require-sigs true --option substitute true
  --option max-jobs 0 --option builders '' --option fallback false)

advertised=false
for cache in "${caches[@]:1}"; do
  if nix path-info "${options[@]}" --store "$cache" "$1"; then
    advertised=true
    break
  fi
done
if [[ "$advertised" != true ]]; then
  echo 'Locked XO output is not advertised by either approved application cache; repair or republish the admitted output upstream before qualification.' >&2
  exit 1
fi

# This is an output path, never a derivation: realise only substitutes its
# closure. Disable local/remote builders and fallback independently as well.
# A source-store copy would incorrectly require every dependency in one cache.
if ! nix-store --realise "${options[@]}" "$1"; then
  echo 'Locked XO closure cannot be substituted from the approved public caches; source builds are disabled.' >&2
  exit 1
fi
# Check actual recursive bytes and signed provenance, including a warm local
# store. Cache signatures may authenticate previously locally built paths.
signatures=()
for cache in "${caches[@]}"; do
  signatures+=(--substituter "$cache")
done
nix store verify "${options[@]}" --recursive --sigs-needed 1 "${signatures[@]}" "$1"
printf 'Locked XO closure bytes and signatures verified across the approved public caches.\n'
