<!-- SPDX-License-Identifier: Apache-2.0 -->
# Native cache/public-consumer cutover: staged, not activated

The current sole-maintainer code-review proposal is described in
[sole-maintainer review](sole-maintainer-review.md). It defers the four immediate
Phase A GitHub review settings below, keeps the App authority gate, and documents
the later independently reviewed transition when another maintainer joins.
Neither this note nor that proposal changes live settings.

This draft migrates the rolling cache publisher and public cache probe to exact
native CI data. It does not select a security leaf, import ledger acceptance or
create a decision record. It does not activate settings, a writer or a workflow
trial. `MAESTRO_NATIVE_PUBLICATION_ENABLED` defaults to `false`; current consumers
remain in place until the explicitly coordinated switch. There is one existing
publication concurrency group, no new scheduled controller and no parallel build.

## Current findings-review route

The reusable risk-file proposal below is historical staging context. The reviewed
Free-plan route now uses a fresh protected environment approval per publication.
See [the current contract and harmless qualification](per-publication-findings-review.md).
No native publisher is activated by that implementation or its qualification mode.

## Real evidence trial and limits

Main `59a6a50a0f022988ff23fbc2a39a3ab92407d843`, CI `41529099686/1`, passed bounded
native preparation: 60 root/NAR identities, ten document/checksum files, current
ISO/inventory binding and the original executed boot from `41379990640/1` at
`4c4aff35d2223c6f03447a32621dd2d36999b26c`. All three current attestations and the
original CI-result attestation were cryptographically verified by standard GH
verification with exact source/signer digests, main ref and hosted-runner checks.

The installed Decider App has no `attestations:read`. No scope was granted and no
installation token was minted for this trial. A temporary GET-only public
transport fetched genuine public API metadata/bundles, checked live repository
1127149753 / owner 256683018 IDs, and delegated cryptography to the real GH
verifier with unchanged constraints. The preparation validator itself was
unchanged. This verifies real data and proofs; it is not a test of the production
workflow-token route. The normal workflow uses its existing GitHub-token
contents/actions/attestations read capabilities, without an App private key.

The receipt remains `authorization:false`, `publicationReady:false`, with no local
NAR/ISO-byte verification claim. Archives/extracted trial inputs were 254,568,766
bytes, under 256 MiB. No Nix evaluation/build, cache write or risk acceptance ran.
The native observations contain 244 raw High and 19 Critical rows; normalized
identities contain 169 High, 16 Critical, 136 Medium and 25 Low. These views differ.
Both must block without a separate explicit risk decision; report mode cannot
make either clean.

## Mandatory policy and immutable data

The existing scan produces findings, source policy, effective policy and
applicability data once. Their exact sizes/hashes are now in the signed native
report. The consumer freezes those files with the native reports and verifies
all source/run/attempt, signature, root/NAR, context, boot and freshness bindings
once in the same invocation. It retains that private snapshot while operating;
no authority capability or cross-invocation proof cache is written.

The mandatory gate verifies the protected current source policy, the exact
machine-disposition merge and the existing `security-verdict.evaluate` result.
It also checks the already-normalized native findings so related-advisory
High/Critical/Unknown severity cannot be downgraded. Blocking rows deny by default
even if `mode` says `report`. Low/medium rows are reported without individual
ledger acceptance. Source-policy exceptions cannot substitute for findings review;
no old exception or blanket acceptance is imported. Technical applicability
metadata is retained; it does not waive an unresolved normalized blocker.

### Explicit human findings-risk acceptance (revised user policy)

High and critical risks may be accepted by an eligible independent human. That is
a separate decision from reviewing implementation code. This replaces the initial
staged gate's permanent rejection of all blocking findings. **Approving a findings
decision accepts the specified risk, including its high/critical issues.** Approval
of this implementation PR does not accept any of the current findings.

The proposed minimal artifact is `automation/security-risk-acceptance.json`.
It is one current source file, with no parent graph, registry packet, historical
ledger traversal or automatic newest-record selection. No real record is added
by this draft. A dedicated PR titled `security: accept findings risk ...` may
change only that file. An independent current human CODEOWNER must submit a
standard APPROVED review on the final exact head. The dedicated artifact's
explicit risk-acceptance type, single-file diff and clearly labeled PR bind what
is being approved. There is no manual hash-paste marker or bespoke admin action.
A standard approval here explicitly accepts the enumerated risks, including
high/critical findings; approval of an ordinary code PR cannot satisfy this path.

The record names that PR, schema/kind/repository, explicit UTC `createdAt` and
`expiresAt`, rationale, HTTPS evidence links, scope hashes and sorted unique
accepted raw/normalized finding fingerprints. Fingerprints are SHA-256 of canonical
JSON (UTF-8, sorted keys, compact separators, no NaN). The raw and normalized views
are both explicit; accepting one view cannot silently accept the other. Only
listed current blocking rows may be accepted. Partial acceptance leaves the rest
blocked. The scope hashes bind *all* current raw/normalized finding content,
product roots/NAR identities, security contexts, all inventory document hashes,
and the listed verifier/policy source files. New or changed findings, roots,
contexts, inventories or policy require a new decision. Missing, forged,
unsupported or ambiguous review evidence fails closed.

The consumer requires the identical record on protected current main, the merged
dedicated PR on main's ancestry, the same record at the reviewed PR head, and an
exact-head approval on this dedicated risk PR from a current human CODEOWNER other than the PR
author. The current repository permission read must still identify that human
as having write/maintain/admin access; revoked access or an unavailable permission
read denies. This is one current repository role, not historical team/admin replay.
A routine code-PR approval, bot, self-review, review of an older head, withdrawn
approval or later changes-requested review cannot accept risk. Reviews are fetched
again before write groups; mutable approval conclusions are never cached across
invocations. Removal/replacement, expiry or dismissal revokes acceptance. This
is standard GitHub review eligibility plus explicit scope, replacing live custom
Super Admin/membership checks, not an equivalent claim to those checks.

**Confirmed expiry policy:** each decision
chooses an explicit expiry no more than 30 days after creation (the existing
source-policy ceiling), with no implicit duration or renewal. The human review timestamp must be at
or after the record's declared creation and no later than now; an old approval
cannot preapprove a future-dated acceptance that activates by waiting. Renewal requires a new dedicated PR and
fresh exact-head human review, rather than extending a prior approval. Fresh independent
scanner DB/evidence and all integrity proofs are still required every invocation.
A fresh scan of identical findings/products/contexts/inventories/policy may reuse
a still-valid review; a changed scope requires new review even before expiry.
Run IDs/timestamps are not the semantic risk identity. This keeps risk review separate from fresh technical validation without replaying
historical decisions. No present findings have been accepted by this proposal.

Risk acceptance executes only after signature, source/run/attempt, coverage,
scanner-health, freshness and retained/executed-boot verification. It cannot waive
missing or invalid evidence, NAR/ISO byte mismatches, drift or failed boot. These
technical failures remain publication failures even with a valid risk review.

Old reports lacking these four new bindings reject. Do not backfill/rewrite an
artifact. A fresh successful signed exact-main qualification after review/merge
is required, followed by the separately authorized workflow-token trial. Without a separately valid explicit risk decision, current
blocking findings must still yield failure and zero restore/upload commands.

Mutable source/policy and scan/DB freshness are checked before each write group
and after verification. Immutable parsing, normalization and attestations are
not replayed for each public request. A graph or policy race aborts; it cannot
undo bytes already uploaded in a previous group. No distributed transaction or
cross-service rollback is claimed.

## Selected cache and public bytes

The gate runs before destination inspection, closure transport or cache writes.
An already complete destination still receives a cold, empty-store probe with
builders disabled. Otherwise the existing signed full transport is retained and
recursively byte-verified; actual selected references/NARs must match both signed
scope and authenticated retained metadata. Only missing paths in the existing
four-root runtime closure can enter Cachix. URLs, keys, signature checks and
upstream fallbacks remain unchanged. No whole-store upload or candidate code
execution is introduced. Full transport retirement waits for its last consumer.

The new consumers use no ledger selector, packet registry, historical approval replay,
live Super Admin check, journal token or upstream authority App token. This is
the previously described security delta, not an assertion that provenance grants
risk acceptance. The required source checks and standard review control the
trusted producer/controller source.

## Exact protection sequence, requiring action-time coordination

`ruleset-20919039-plan.json` records a public readback and two prospective bodies.
Never blindly apply this stale snapshot: fetch the complete current ruleset,
apply only the named deltas, preserve every other live field and reject unexpected
changes for review. No PATCH is performed by this code.

1. Review the exact draft head independently and pass its hosted tests. Verify
   the native variable is absent/false. CODEOWNERS names `@declarative-dale`;
   confirm write eligibility. A Dale-authored PR needs another eligible human
   CODEOWNER and cannot be self-approved; no bot/bypass substitutes for that.
2. Merge/converge the reviewed source contract and install Phase A: one human
   approval, stale dismissal, last-push approval and CODEOWNER review. Keep the
   existing App check while verifying these protections are effective. The source
   policy-drift contract now expects Phase A; until live convergence its scheduled
   drift check should correctly fail. Do not disable that check to hide the gap.
3. Preserve `require_extra_approval_for_unattributed_changes:true`, empty bypass,
   merge-only/thread resolution, deletion/non-fast-forward protection, every
   queue parameter and all five Actions CI/CodeQL bindings (15368). Phase A changes
   only four review values. Phase B removes only `Maintainer decision authority`
   from App 5384448, and is **not yet executable** until all consumers below have
   migrated and their parity/reference checks pass.
4. Get fresh signed main evidence, verify the production read-token path, prove
   the mandatory gate blocks the real high/critical findings, and observe zero
   destination writes. A clear result is required before any publication.
5. Stop/inspect in-flight legacy writer operations and exact destination outcomes.
   Only then set the reviewed native cache/probe switch. This first native route
   is explicit manual exact-run operation; it does not authorize automatic cache
   publication from future runs. The old cache job is disabled by that switch;
   the public probe also becomes explicit manual input, with no newest selector.
6. Versioned releases, release continuation and reconciliation writers must be
   disabled/migrated in a separately reviewed consumer-parity step **before full
   cutover or Phase B**. Do not treat this rolling-cache draft as their migration.

The live `release` and `publication` environments currently have protected-branch
policies only. `release` has no human-review protection. Versioned-release
activation is blocked until required human reviewers and self-review prevention
are installed/verified in the separately reviewed release migration. No reviewer
or environment permission is changed here.

## Remaining consumers and deletion boundary

- Keep current native CI, complete comparison and all twenty obligations. Do not
  retire graph/retained/equivalence jobs merely because this boundary passes.
- Migrate versioned release asset staging/splitting/checksums and explicit human
  publication; preserve existing versions and reject conflicting/partial bytes.
- Keep installer/deploy `verify-state` / `verify-inventory` and immutable original
  media bindings; they already use native attestations rather than leaf selection.
  Prove cold installer consumer parity before changing their pointer format.
- Move security refresh to authenticated inventories with independently fresh DB
  scanning, without ledger enumeration or closure downloads for scan-only work.
- Stop legacy scheduled decision/continuation writers, then remove their callers.
  Keep technical product/scans construction and pure normalization/cache/transport
  helpers under native ownership before deleting authority modules.
- Only after those references/parity checks pass may Phase B remove the old App
  gate and controller/packet/journal workflows be deleted. Preserve every historical
  `automation/decisions/**` record unchanged.

Rollback holds new writers, inspects partial public effects and restores the
reviewed prior caller contract through normal review. Keep stronger source-review
protections. The previous ledger remains ambiguous, so rollback may restore a
safely blocked publisher. It cannot retract previously downloaded/published bytes.

## Review decisions still required

The user confirmed maximum-30-day expiry and no automatic renewal. Same-scope
fresh-scan reuse does not extend expiry; renewal needs fresh human review. The
standard current human CODEOWNER is the
risk approver; changing that eligibility requires separate reviewed policy. The
current sole owner cannot approve their own decision PR, so another eligible
independent author/reviewer is necessary. This draft adds no members or bypasses.
Versioned releases and security-refresh consumer parity, protected release review,
fresh producer evidence, exact-head independent review and Phase A settings
verification remain prerequisites; the native feature flag stays false.
