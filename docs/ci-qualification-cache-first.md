<!-- SPDX-License-Identifier: Apache-2.0 -->
# Cache-first qualification reuse

The #229 queue baseline spent approximately 9m51 downloading/restoring the
original closure before a 2m09 fresh scan. These are observed step timings,
not guaranteed savings. Its retained transport was about 2.85 GB; stored
artifact size is not wire traffic. The independent #234 lock-update build took
about 58 minutes, and an earlier 53-minute build was cancelled after a head
update. This change addresses the reuse transport, not that full build.

The existing inventory/scan job now downloads its exact successful protected
CI producer's small metadata artifact first. `QUALIFICATION_METADATA_ONLY`
is an internal step input restricted to an explicitly required CI run: it
cannot enable publication discovery, release selection or registry fallback.
It does not authenticate or authorize its contents by itself.

The existing restore command authenticates original product and scan signatures,
revision, candidate-evaluated root coverage, inventory bytes and inventory/NAR
bindings before querying caches. It first uses already present store outputs.
Otherwise it asks ordinary Nix to substitute the exact output paths, using only
the runner's baseline plus the exact cache URLs and keys already declared in
`flake-file.nixConfig`. Those declarations are packaged once for this command;
no second URL/key list is introduced. A 15-second dry-run probe
precedes a 120-second fetch. Local builds, remote builders and build fallback are
disabled, signatures are required, and derivation paths are rejected. No flake
evaluation or build is added to the cache attempt.

Every successful local/cache path still passes the existing exact root/NAR
verification. A mismatching NAR is an integrity failure, never a cache miss.
Unused artifact parts are not fetched or validated on a local/cache hit; the
actual used outputs are verified instead. There is no claim that an unused
archive was verified. Cache unavailability/timeouts may fall back only to the original producer's
existing artifact transport. Before that lazy fetch, the original run, attempt,
revision, CI workflow, successful protected producer and complete artifact
inventory are checked again. Archive digests, exact part inventory, extraction
bounds and NAR verification remain unchanged. API, signature, manifest and import
failures do not trigger another identity, registry selection or approval waiver.

| Path | Primary metadata download | Bulk artifact download | Artifact restore | Fresh scan |
| --- | --- | --- | --- | --- |
| Before | 1 | 1 | 0 or 1 | 1 |
| Already-local hit | 1 | 0 | 0 | 1 |
| Configured-cache hit | 1 | 0 | 0 | 1 |
| Cache miss | 1 | 1 | 1 | 1 |

A configured-cache hit can still download NARs; this is not a zero-network or
wire-byte savings claim. A cache miss can add up to 15 seconds for the probe;
an availability race after a successful probe can add up to 120 seconds before
artifact fallback (plus existing process-group cleanup). Old producers that
bundled their transport in the primary artifact cannot avoid those bundled
bytes. No cache is populated by this PR's workflows, and no trust setting,
credential, permission, security gate, provenance contract or timeout is widened.
The existing fresh database scan and shipped-file/npm applicability checks still
run once, against realized outputs. This never reuses findings approval.

The bounded fixtures assert zero bulk transfers/imports for a hit and exactly
one lazy fetch/import for a miss, with authentication before any cache work.
They reject changed roots, NARs, producer attempts/revisions and incomplete
artifact inventories. A real tiny subprocess verifies the no-build command
contract, cache-probe failure, timeout cleanup and rejection of derivation or
non-store arguments without running Nix or downloading a closure locally.

Hosted validation must report `transportSource` from the restore receipt and
compare metadata download, substitution/fallback and scan times on equivalent
products. A same-root queue should preserve all inventory/root/boot coverage and
fresh scanner checks. Cold-cache fallback must also pass. Neither fixture work
counts nor a single warm run proves broad runner headroom or total merge savings.
Full realization, installer boot and all twenty audit obligations remain intact.
Avoid refreshing a long-running lock-update PR's head unless necessary: a changed
head correctly requires new CI and review, and this PR does not reuse unsigned
PR build artifacts as protected evidence.

References: [Nix realisation](https://nix.dev/manual/nix/stable/command-ref/nix-store/realise)
and [Nix build/cache settings](https://nix.dev/manual/nix/stable/command-ref/conf-file).

The local public-cache descriptor probe returned HTTP 403; no alternate identity
or route was attempted. Current hit rate and hosted timing benefit remain
unverified. In particular, this is not evidence that all sixty current roots are
available from the configured caches.
