<!-- SPDX-License-Identifier: Apache-2.0 -->
# Inventory reuse follows content, not CI routing text

The qualification inventory key previously hashed the entire
`.github/workflows/ci.yml`. A concurrency, label or routing-only edit therefore
invalidated an otherwise identical inventory and regenerated SBOMs. The key now
retains exact evaluated roots/derivations, generator/verifier/tool identities,
upstream XO supply identity and every existing asset-policy source except that
workflow file. Current workflow validation/review and signed producer checks
remain separate and unchanged.

This permits reuse of an older authenticated inventory under the same content
and current verifier; it does not reuse an approval or skip verification. The
resolver still authenticates the protected-main producer, immutable state,
checksums/signatures and exact inventory key before reuse. Current inventory
binding/coverage checks and the independently fresh database scan still run.
Changes to actual roots, generator, verifier or retained policy inputs invalidate
the key. There is no fallback that reinterprets an old fingerprint under the new
algorithm; its introduction causes a normal one-time cache miss.

## Bounded validation

The existing hosted equivalence job now mutates CI workflow text and requires
unchanged qualification identity and appliance/ISO outputs. A complementary
inventory-generator mutation must change qualification identity while leaving
appliance/ISO recipes unchanged. This performs real Nix evaluation in hosted CI;
local subprocess fixtures only verify that the driver rejects unexpected
invalidation, ignored generator changes and evaluation failure, and restores
mutated files on every exit. They do not prove the Nix result locally.

All existing twenty audit obligations, public outputs, pinned inputs, VM/boot
behavior, scanner health/freshness, inventory/verifier policy and required checks
remain. No ledger record, findings acceptance, credential, permission, ruleset or
publication flag changes. This is independent of the findings-review choice.

## Observed baseline and limits

The #215 queue and post-main runs both used commit
`4f19ea4c17d9dcaf4702eb5baa77375b851a8f1a`:

| Observation | Queue 41602798270 | Main 41607896104 |
| --- | ---: | ---: |
| Assemble qualified media/evidence | 469 s | 449 s |
| Fresh database scan | 109 s | 127 s |
| Installer build | skipped | skipped |
| Actual QEMU boot step | skipped | skipped |
| Retained boot binding/verification | 163 s | 157 s |

These are step durations, not pure SBOM timings, wire bytes or additive savings.
Source inspection shows the assembly's `refresh-evidence` path runs sbomnix and
inventory annotation rather than copying authenticated inventory. The inventory
fingerprint included the changed CI workflow. No claim is made that every second
of assembly was caused by inventory generation, or that all queue/main work is
eliminated by this patch.

Before/after acceptance requires hosted mutation results and signed reuse
receipts for a later routing-only edit, matching roots/documents and one fresh
scan, with generator/root changes still forcing regeneration. The first run with
a new key cannot demonstrate a cache hit. Discovery still uses successful main
producers: reuse of an identical merge-queue artifact after merge would be a
separate producer-trust/provenance change requiring review, not an implicit part
of this optimization. Historical evidence and existing public artifacts remain.

Sources: [queue run](https://github.com/closure-labs/maestro/actions/runs/41602798270),
[main run](https://github.com/closure-labs/maestro/actions/runs/41607896104),
`modules/ci/graph/identities.nix`,
`modules/features/installer/_source/qualification-assets.sh` and
`modules/features/installer/_source/qualification-resolve.sh`.
