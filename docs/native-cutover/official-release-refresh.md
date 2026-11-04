<!-- SPDX-License-Identifier: Apache-2.0 -->
# Official release refresh: inactive identity preparation

The remaining refresh consumer is `security.yml:release_candidates`. It selects
an official product through `ci:decision:download`, refreshes it through the legacy
consumer and uploads retained product evidence again. Rolling native refresh is
already prepared separately; it does not cover a shipped version that differs
from main. Keep this coverage until its replacement is reviewed and qualified.

The locator preparation adds one private verifier and negative fixtures. It reuses the
existing `native-release-staging.json` produced by native ISO staging. There is
no new descriptor schema, ledger, registry packet, approval record, workflow,
credential, repository variable or controller. It is not directly exposed as a task or package.
All existing gates, writers and scheduling behavior are unchanged. The separately
prepared [explicit official refresh route](official-refresh-route.md) is the only
opt-in caller; it still requires reviewed producer integration and separate trial
authorization. No automatic schedule invokes the locator.

The locator accepts one explicit version tag, receipt file, publication signer
revision and current policy revision. It freezes at most 1 MiB of regular receipt
bytes; uses standard `gh attestation verify` with the existing release workflow
signer, exact signer/source revision, protected main source and hosted-runner
restriction; checks the SLSA subject digest; and binds the receipt to the exact
uploaded asset of that stable GitHub release. Product and signer revisions must
be ancestors of current main. Wrong/moved tags, changed main, draft releases,
ambiguous/missing assets, malformed identities and unavailable signatures reject.

The returned tuple is **scheduling metadata only**. `authorization`,
`publicationReady`, `inventoryVerified`, `isoBytesVerified`, `narBytesVerified`
and `findingsAccepted` are all false. A prior findings verdict embedded in a
staging receipt is never reused as approval. No ISO or closure payload is fetched
by this locator, and it makes only metadata GETs and signature-verification calls.
It uses the existing bounded verification response helper (4 MiB, 90 seconds).
GitHub's [artifact attestation verifier](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
provides the cryptographic verification; repository parsing does not substitute
for it.

## Separate integration increments and exit criteria

1. **Receipt retention, after #227's correction/review.** In the existing native
   release signer job, attest the already-generated staging receipt with the
   pinned standard attestation action. Retain that same small file as an immutable
   release asset after the existing final authorization checks. Extend the
   writer's exact asset contract and tests; do not regenerate inventory or add a
   second closure transfer. This draft does not change that writer or #227.
2. **Official refresh wiring.** Obtain the explicit published tag and signer
   identity from a reviewed selection route. Run this locator, then reuse the
   existing native inventory verifier on the exact original run/attempt/source
   and original executed-boot proof. Verify that its signed ISO digest matches
   the receipt. Preserve full root/NAR, context, inventory-document and upstream XO
   coverage. Restore/check actual NAR bytes once, then scan existing SBOMs once
   with fresh databases and real shipped-file/npm checks. Emit signed health
   only; no SBOM regeneration, closure re-export or product re-upload.
3. **Deduplicate by authenticated product identity.** If rolling and official
   targets resolve to the same verified immutable inventory, scan once and use
   that exact health for both consumers. Different products require distinct
   scans. Do not deduplicate on version strings or commit equality alone.
4. **Cutover and retirement.** Qualify both distinct-product and same-product
   cases, consumer freshness, original boot and full coverage in hosted CI.
   Only then replace `release_candidates`, stop its legacy transfer loop and
   remove ledger/controller references after a complete reference audit. Preserve
   historical records. No live flag or security setting changes in these drafts.

Current releases lack this newly attested public receipt; they must reject here.
Do not manufacture provenance for an old release or silently select current main
instead. Until official coverage is proven, the existing official refresh remains
in place. Missing/expired original artifacts are an explicit availability failure,
not permission to rebuild, select different bytes or waive freshness/integrity.

Fresh health cannot publish by itself. Any later publication still needs a fresh,
findings-specific human approval and current eligible access. This locator does
not change the accepted GitHub Free remove-and-restore limitation, sole-maintainer
review policy or evidence requirements. Its metadata checks do not establish
actual ISO/NAR-byte verification, hosted performance, live token compatibility or
successful production cutover.
