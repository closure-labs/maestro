<!-- SPDX-License-Identifier: Apache-2.0 -->
# Captured sbomnix runtime validation

Maestro PR #78 qualification succeeded, but its sbomnix process used the
Nixpkgs wrapper's Nix 2.31.5 rather than the captured Determinate 3.21.9 CLI
(Nix 2.34.8). That explained the unsupported `build-provenance-tags`,
`eval-cores` and `lazy-trees` settings in the qualification log.

The pinned sbomnix 1.7.6 recipe selects `nixVersions.nix_2_31` directly;
overriding its `nix` argument has no effect. Maestro overrides that exact slot,
checks the original and resulting wrapper paths, and routes `nix`, `nix-store`
and `nix-env` through its runtime adapter. Hosted commands require the captured
executable and matching companions. Local commands retain the pinned fallback.

Fresh-cache parity exposed an additional compatibility issue: Determinate's
lazy-tree flake metadata omits `path`, which sbomnix needs to recognize the
locked Nixpkgs source. Simply changing the wrapper silently removed metadata
from 339 CycloneDX components and 335 SPDX packages, despite unchanged counts.
That candidate was rejected. The compatibility patch retries only affected
metadata requests with `lazy-trees=false` and rejects malformed responses or
missing/empty or non-directory materialized paths. It preserves the original appliance flakeref,
locked metadata enrichment, tool version, and inventory formats.

The packaged qualification fixture exercises actual sbomnix and nixmeta:
captured flakeref evaluation, lazy metadata materialization, captured `nix-env`,
missing companions/runtime pointers, missing/empty/nonobject metadata, and
nonexistent, relative or non-directory source paths.
It belongs to the five-target evidence plan; the early validation plan retains
its nineteen targets and does not acquire the full SBOM tooling closure.

## Inventory and measurement

Both raw inventories describe the same appliance output,
`/nix/store/fcay17zfc6i423x5jq5z7743rfg1kkdw-nixos-system-maestro-26.05.20261010.6fcc160`.
The baseline used the unmodified pinned sbomnix wrapper; the compatible candidate
used the exact executable captured in PR #78's hosted log. Each had a separate
empty metadata cache. Complete canonical CycloneDX and SPDX comparisons passed:
810 components, 811 dependency rows, 811 SPDX packages and 3079 relationships.
Comparison sorts unordered arrays without removing duplicates and excludes only
CycloneDX `serialNumber`/`metadata.timestamp` and SPDX
`documentNamespace`/`creationInfo.created`. Licenses, descriptions, vendors,
identities, provenance properties and graph edges remain compared.

Complete local qualification assembly also passed with the final package and
runtime fixture. The assembled inventory matches the previously qualified
baseline under the same normalization: 4180 CycloneDX components, 4181 dependency
rows, 811 SPDX packages and 3080 relationships, including the XO external-document
link. Separate enrichment of old/new raw inventories through the same captured
CLI also matches, retaining derivation/patch/runtime context digests. The XO
inventory is byte-identical. The appliance and installer outputs are unchanged.

| Fresh metadata cache | Wall time | Peak RSS (KiB) |
| --- | ---: | ---: |
| Original wrapper | 112.16 s | 7,324,164 |
| Captured CLI with metadata compatibility | 134.96 s | 5,991,756 |

These are one-pass workstation measurements alongside other validation, not
isolated hosted performance acceptance. The correct candidate was slower in
this sample. The initially faster candidate lost metadata and is excluded
from performance claims. CLI alignment is a correctness change; no speed gain
is asserted from these measurements.

The local receipts and complete comparison inputs are under
`/tmp/maestro-sbom-parity`, including the rejected comparison, corrected parity
receipt, native checks, packaged fixture logs and timed command output.
