<!-- SPDX-License-Identifier: Apache-2.0 -->
# Inventory and fresh scan on one hosted runner

The `qualification` job now assembles or authenticates the inventory, verifies
its local root/NAR and document identities, scans fresh databases, and retains
the final native report/transport on the same unprivileged runner. It does not
upload and restore an intermediate `maestro-inventory-transfer` artifact.

The existing inventory generator runs once on fresh inputs; authenticated reuse
continues to use the existing producer verifier. SPDX/CycloneDX formats and
upstream XO inventory/applicability metadata contracts remain unchanged. Scanner update checks, database
age/health checks, native evidence timestamps and Cargo coverage are unchanged.

`ci:inventory:bind` retains the small same-attempt inventory/ISO binding. Its
`transport: null` explicitly means local metadata, never a restorable archive.
`ci:inventory:verify` checks the exact graph roots/NAR identities and every native
inventory/checksum document before scanning. Old archive manifests remain valid
for actual transport consumers. Imported staging chunks are removed only after
local roots verify; index/evidence documents and all remote/final artifacts stay.

The combined job exports the actual scan step conclusion. Security verification,
signing and the required verdict require it plus the successful combined job;
failed/skipped scans cannot become successful job aliases. The final
`maestro-security-report`, `maestro-distribution-transport`, native producer
identity, attestation/signing jobs and publication consumers retain their existing
contracts. All twenty validation obligations, independent comparison, equivalence,
CodeQL/Gitleaks, authority check, merge queue and essential boot behavior remain.
No cache key, trusted endpoint, credential or permission is added or changed.

## Cost and resource validation

Measured baseline on main `901e1a51…`, run 41317864638:

- Intermediate inventory artifact: 2,848,974,123 stored bytes.
- Intermediate export/upload: 1m57s; scan download/restore: 3m35s.
- Fresh scan step: 2m32s; final retained transport: 2,848,727,370 stored bytes.

These are artifact sizes and step durations, not wire bytes or guaranteed wall
savings. Inventory/scan share one store now; installer boot waits for the combined
job rather than overlapping a separate scan runner. Preserve that test and
measure the changed critical path instead of claiming the sum as a speedup.
Changing the inventory binding verifier naturally changes the existing boot-policy
hash, so old boot proof must not be reused across that change.

Fresh inventory and scan phases record GNU time elapsed/CPU/max-child-RSS plus
disk-before/disk-after snapshots under `maestro-qualification-diagnostics`, uploaded
even on failure. Maximum child RSS is not aggregate cgroup/runner peak; disk
snapshots are not continuous high-water marks. Reuse still has the existing step
and restore diagnostics. Static fixtures establish no hosted headroom guarantee.

Co-location retains inventory tools while scanning and final export creates its
own temporary cache/archive/parts. Verified incoming chunks are released before
that export to avoid retaining another downloaded multi-GiB archive. The existing
runner preflight and job timeout remain unchanged. Hosted disk/RSS observations,
OOM/disk failures and actual final artifact sizes must determine suitability.

## Same-coverage before/after checklist

1. On the draft's hosted CI, require all twenty ordinary audit targets,
   independent comparison/equivalence, native verification and required verdict
   to pass. Require actual ISO boot whenever current inputs/verifier demand it;
   never count skipped boot execution as a new VM pass.
2. Confirm exactly one inventory generation/reuse path and fresh scan; no
   intermediate export/upload/download/restore. Confirm phase failures block
   security/signing/verdict and retain failure/resource diagnostics.
3. Compare planned root/NAR sets, native subjects, coverage manifest, runtime
   contexts, upstream XO inventory and SBOM document hashes. Changed source or
   verifier identity may require fresh artifacts; do not claim byte parity across
   different products. Finding counts may legitimately change with fresh databases.
4. After independent review/merge, inspect the normal protected-main qualification
   for the unchanged final evidence/transport shape, producer identity and
   attestations. Draft PR runs do not exercise the protected-main signing/export
   side effects. No manual production/recovery dispatch is part of this change.
5. Record before/after step durations, artifact bytes and the resource diagnostics.
   Reject corrupt/missing roots, swapped evidence or stale/unhealthy scans. Report
   resource limits and scheduling tradeoffs honestly before further rollout.

This is independent of #203's ordinary-flake trial. Its branch/auto-merge and
required review/protection settings are untouched. Inspector/recovery remain paused.

Native closure copy diagnostics stream to the job log; only the last 8 KiB of
stderr is retained in memory. Failed copies retain `copy-export.failure.json`
or `copy-restore.failure.json` beside existing transport diagnostics, including
exit/timeout status, elapsed time and temporary-filesystem free-space snapshots.
Receipt write failure does not replace the native failure. These snapshots do
not establish peak disk or memory use. JSON-producing Nix operations retain their
existing capture path; roots, NAR checks, compression, deadlines and transport
manifests are unchanged. The change exposes failures and bounds capture memory;
it does not establish the cause of the previously observed native abort.
