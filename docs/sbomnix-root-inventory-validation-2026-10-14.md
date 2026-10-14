<!-- SPDX-License-Identifier: Apache-2.0 -->
# Root Nixpkgs inventory metadata correction

The existing sbomnix 1.7.6 scanner selected `locks.nodes.nixpkgs` directly.
Maestro's lock graph declares `locks.root = "root"` and that node selects
`inputs.nixpkgs = "nixpkgs_5"`. The literal `nixpkgs` node belongs to another
input. This bug predates the captured CLI alignment in PR #80; that PR preserves
baseline inventory parity and is independently valid.

The incorrect node selects revision
`c5c4a43b0e8056328ec4529f735cabdb8f1942bb`, materialized as
`/nix/store/vin7xkmskj4k065z1w7bwwwwp4dbfv93-source`.
The declared root selects revision
`6fcc160353f63555b560f25588925133c8f61f2a`, materialized as
`/nix/store/hbd89dn4si5jb3imhymh1bapmf7i5jc4-source`.
Both paths and revisions were independently obtained using the exact
Determinate 3.21.9 CLI captured in PR #78's hosted qualification log.
All 335 baseline `nix:position` properties used the incorrect source.

The follow-up resolves the input from the declared lock root. Root-relative
`follows` paths are traversed through input edges. Cycles, missing nodes,
invalid references, missing locked objects, and incomplete or unsupported
locked references fail explicitly. Direct Nixpkgs flake recognition, captured
CLI companions, lazy-tree materialization, and directory validation retain
PR #80's behavior. Changing the sbomnix package also changes the existing
qualification evidence fingerprint, preventing reuse of old evidence.

## Verified inventory changes

The freshly generated inventory describes the same appliance output,
`/nix/store/fcay17zfc6i423x5jq5z7743rfg1kkdw-nixos-system-maestro-26.05.20261010.6fcc160`.
Raw inventories retain 810 CycloneDX components, 811 dependency rows,
811 SPDX packages, and 3079 relationships. The complete enriched CycloneDX
inventory retains 4180 components and 4181 dependency rows. The separate XO
inventory is byte-identical.

Canonical comparison sorts arrays while preserving duplicates and excludes
only CycloneDX `serialNumber` and `metadata.timestamp`, plus SPDX
`documentNamespace` and `creationInfo.created`. All component identities,
names, versions, PURLs, CPEs, graph edges, root metadata, derivation and patch
provenance, runtime context, and other top-level fields remain identical.
Only the following source metadata differs:

| Field | Affected records |
| --- | ---: |
| CycloneDX `nix:position` | 416 |
| CycloneDX homepage property | 81 |
| CycloneDX descriptions added | 82 |
| CycloneDX licenses added | 81 |
| SPDX summaries added | 82 |
| SPDX homepages added | 81 |
| SPDX `licenseInfoFromFiles` added | 81 |
| SPDX `licenseDeclared` and `licenseConcluded` | 36 each |

All 418 changed CycloneDX records match the actual root source's metadata
scan of 95,766 records. License values were checked with the packaged sbomnix
serializers. All 36 declared/concluded license transitions are `NOASSERTION`
to a single license documented by that source, including bind (`MPL-2.0`),
curl (`curl`), expat (`MIT`), and glibc (`LGPL-2.0-or-later`). Existing license
information is retained. Multiple-license packages gain their source license
list while preserving sbomnix's existing `NOASSERTION` declaration policy.
No npm vulnerability policy changes are included.

## Checks and measurements

The packaged fixture invokes the actual `nixmeta` scanner with a captured fake
CLI. Its deliberately misleading first `nixpkgs` node discriminates the old
bug from root selection. A differently named root, nested follows, and eleven
malformed graph/reference cases are exercised. Invalid graphs never reach
`nix-env`. Existing captured CLI and materialization fixtures also pass.
Native Bash syntax, ShellCheck, Nix formatting, flake evaluation, and the
complete nineteen-target repository audit pass.

| Workstation run | Wall time | Peak RSS (KiB) |
| --- | ---: | ---: |
| Root correction, empty metadata cache | 107.37 s | 6,182,040 |
| Final package, validated warm cache | 67.31 s | 1,675,808 |

The final package's canonical inventory equals the first corrected inventory.
These are correctness measurements under workstation load, not an isolated
hosted performance acceptance or a claimed speed improvement. Complete input,
field-by-field attribution, source metadata, and timing receipts are retained
under `/tmp/maestro-inventory-fidelity-evidence`.
