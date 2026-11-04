<!-- SPDX-License-Identifier: Apache-2.0 -->
# Native release receipt retention — inactive

The native ISO staging command already emits `native-release-staging.json` with
exact product/run/attempt, original executed-boot media identity, ISO digest and
release asset hashes. Retain this existing small file as an immutable release
asset so official-product refresh can locate the original product without
historical ledger selection or downloading the ISO merely to identify it.
There is no new receipt schema, packet registry, provenance service or controller.

This preparation changes only the inactive native release writer and its tests.
Before its first public mutation, it now verifies a standard SLSA attestation for
the frozen receipt bytes, using the existing `release.yml` signer, exact reviewed
policy/source revision, main source ref and hosted-runner restriction. The existing
bounded CLI verification helper enforces a 4 MiB response cap and 90-second call
timeout. Missing/invalid signature or changed signed bytes rejects before tag,
draft, asset upload or publication. Real ISO/SBOM bytes and their separate final
SLSA/SPDX attestations remain independently verified.

The receipt is copied once into the existing private asset snapshot (at most
1 MiB), checked against the verified product/original media tuple and included
in the existing exact asset reconciliation. Disk admission reserves up to 3 MiB for the receipt and bounded readback
streams while retaining the existing 256 MiB reserve. No closure or ISO transfer, SBOM
regeneration, restore or scan is added. The file cannot hash itself: its SLSA
subject supplies that binding; its existing assets map continues to describe
only payload assets. The reconciler separately binds the receipt digest.

## Dependencies before activation

- #227's separately pending permission correction must be pushed, pass CI and
  receive fresh exact-head human review. This PR does not include that correction
  or edit its branch/workflows.
- In a separate integration after that reviewed source converges, add one pinned
  standard attestation action for the existing staging receipt inside the same
  release signer job, after staging and before the writer. Its subject must be
  the exact original receipt file, not regenerated JSON. Until that attestation
  exists, native release writing fails closed. No flag is activated here.
- #228's inactive locator can then authenticate this asset and obtain the original
  CI/media tuple. It still cannot grant risk acceptance or replace complete
  inventory, executed-boot proof, actual NAR-byte verification and fresh scanning.
- Qualify the full distinct-official/rolling and identical-product cases before
  replacing the old official refresh loop. Old releases without this receipt are
  not silently grandfathered or rewritten. Existing active publication/refresh
  behavior and all historical records remain unchanged.

The public receipt contains existing product/evidence provenance and its prior
review verdict. Consumers must treat that verdict as historical metadata, never
an approval for another publication. This code neither accepts current findings
nor changes the per-publication human gate or current access/evidence checks.
The GitHub Free sole-maintainer and remove/restore limitations remain unchanged.

Fixtures cover exact immutable receipt retention, missing/forged/failed signature,
mutation during verification, mismatched producer/media/byte claims, live main
races, failure cleanup and real bounded subprocess verification alongside final
ISO/SBOM attestations. Hosted tests and independent review are still required;
fixtures do not prove live token compatibility, full-size disk headroom or
successful production publication.

## Fresh-review retries and least-privilege destination checks

A raw staging receipt contains per-invocation review and health/policy context.
Regenerating it after a fresh review can change its digest while every payload
asset is identical. Never overwrite an existing immutable public receipt to
accommodate that change. The corrected writer authenticates its newly staged
receipt first, then reads at most 1 MiB of the one existing receipt asset, checks
its GitHub size/digest, original source/run/attempt/media and exact payload asset
map, and verifies its original release-workflow signature and signer ancestry.
It retains those original bytes. The old verdict is historical data only: it is
never assigned to current risk state, used as approval, or allowed to waive fresh
findings, access, main/policy, evidence or final remote-byte checks.

This supports already-published no-op verification and a partial existing draft
without replacing or reuploading its receipt. The existing asset reconciler
rechecks remote bytes and identities, uploads only missing payloads, and performs
its existing live authorization before each write group and final publication.
Signature/transfer/metadata failures block; none are treated as absence.

GitHub's token cannot create a release for an older commit when its workflow Git
tree differs from default main. Read-only preflight and the writer now check the
exact destination and enforce that ceiling when creation is known to be needed.
The sanitized CLI exposes the fixed `ReleaseWorkflowPermissionError` diagnosis,
without printing raw API/credential errors.
Equal source/policy commits need no workflow-tree reads; older commits with an
unchanged workflow tree remain supported. Existing exact tag/release destinations
can resume or verify without needing workflow-write credentials.

A read-only token may not see a draft. When an exact tag exists but no release is
visible, preflight explicitly reports `requiresWritableReadback`; it does not
claim authenticated draft absence or authorize creation. After the human gate,
the writer uses its existing contents-write view to rediscover the destination
and recheck creation eligibility before any mutation. No permissions, identities
or trust are expanded. Use fresh exact-main qualification to bootstrap a genuinely
new release after the reviewed changes converge. The nonpublishing gate trial
does not qualify destination writes or accept findings.
