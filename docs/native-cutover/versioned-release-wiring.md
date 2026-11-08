<!-- SPDX-License-Identifier: Apache-2.0 -->
# Inactive native versioned-release wiring

The existing `MAESTRO_NATIVE_RELEASE_ENABLED` default is still `false`. This
change does not set a variable, configure an environment, dispatch a run, accept
findings or publish a release. Normal CI validates the code; it does not exercise
the protected production path.

The reviewed route is an explicit manual `release.yml` invocation
with `native_release=true` and exact original CI run/attempt/source, optional
fresh-health run/attempt and any required original executed-boot tuple. The
source's committed VERSION is used; there is no automatic version mutation,
new release build, risk ledger selection or newest-decision recovery.

1. The read-only `native_review` job authenticates complete signed native evidence
   and mandatory fresh findings. It derives VERSION and the unique original
   installer artifact ID from the verified product/boot source. It saves the
   bounded findings review and context digest for human inspection. Metadata
   identifies bytes to fetch; it does not claim those ISO bytes were verified.
2. Only a successful review preflight can start the direct `native_finalize` job
   in the same `release.yml`. It waits on `findings-risk-review`. Approval explicitly
   accepts the displayed findings risk, including high/critical issues, for this
   one publication. Code review is separate. Missing or changed environment,
   review, context, current reviewer access, evidence or main still rejects.
3. The gated job downloads the exact media artifact ID and verifies its actual
   ISO against signed original CI and directly executed boot proof. The reviewed
   staging command checks approval independently, stages the existing ISO parts
   and original SBOMs, and retains a verified final-name ISO snapshot.
4. Standard GitHub actions create final-name SLSA and SPDX attestations **inside
   release.yml**, preserving the existing pinned signer. The native writer
   independently revalidates evidence, findings review, current main/policy,
   staged byte hashes and both attestations before normal immutable release writes.
   Mutable approval/access/freshness checks remain before each write group.

GitHub documents [reusable workflow attestation verification](https://docs.github.com/en/enterprise-cloud%40latest/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating#step-2-verifying-artifact-attestations-built-with-a-reusable-workflow).
No signer allowlist, signing key, cache key or provenance predicate is weakened.
The immutable product source S and current policy/signer source M remain distinct
and bound. The public tag targets S; final-name attestations identify reviewed M.

## Reuse and resource limits

The preflight and gated job independently read metadata so approval cannot grant
an unverified bundle. Within the gated job, raw native inputs and optional fresh
health are downloaded once and reused between staging and writing. They remain
untrusted data: each consumer verifies them rather than caching authority. No
original closure is restored, rescanned, re-exported or re-uploaded in this ISO
promotion path. Fresh complete CI or health is already mandatory. There is no
SBOM regeneration. The original complete SPDX inventory is bound to the final ISO.

The code directly verifies all final ISO bytes and retains signed root/NAR
identity coverage, but it does **not** claim an additional NAR-payload restore or
cache readback here. Cachix publication keeps its separate actual NAR checks.
Existing ISO/asset caps, disk-headroom checks and command deadlines remain; no
compression or existing timeout is raised. The standard artifact download occurs
on an ephemeral hosted runner, never the workstation. Full-size download,
staging/asset-snapshot peak disk, runtime and real signer/token behavior
still require a separately authorized hosted qualification before activation.

## Credentials and legacy isolation

The native jobs run directly in the existing `release.yml`, retaining the pinned
signer path. They receive **no Decider private key** or Cachix credential. The
original reusable interface still requires DECIDER_KEY for its legacy caller;
its two legacy inputs and permission envelope remain unchanged.

GitHub validates reusable-workflow permission ceilings across all callee jobs,
including conditionally skipped jobs. A new read-only native reusable caller
would therefore fail because legacy jobs require Actions and pull-request write.
Direct native jobs avoid that incompatible call without increasing any grants.
The native writer keeps Actions read and contents/attestations/artifact-metadata/
OIDC write; the preflight remains read-only. See GitHub's
[permission downgrade rule](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations).

The exact findings-review root is replaced with `release.yml`; the previous
`release-publication.yml` root is rejected rather than added to an allowlist.
The gated finalizer shares the existing `maestro-publication` FIFO to serialize
writes with other publication jobs. No workflow or job gets broader permissions.

With the flag disabled, existing legacy dispatch/schedule behavior is retained.
A native request never falls back to legacy selection. Upon a later explicitly
approved activation, the same flag excludes the old version-preparation,
continuation and official-publication paths. Future native releases require
VERSION to be committed through ordinary protected review before the selected
CI product is built. There is no second version-bump controller.

The distinct scheduled official-product refresh still needs its native consumer
migration and coverage parity before ledger/recovery controllers can be retired.
Historical records are preserved. Do not call this PR a completed production
cutover, or enable it merely because unit/PR checks pass. The GitHub Free gate's
accepted sole-maintainer and unobserved remove/restore limitations are unchanged;
no present findings are accepted.

## Activation and rollback

Before activation: independently review this exact head; obtain successful fresh
signed main qualification; separately approve/configure the exact findings
review environment and qualify its real token/approval path; complete native
consumer/protection migration and full-size release qualification. A findings
acceptance must be a separate explicit human action. The run's maximum thirty-day
approval window, no automatic renewal and independent evidence expiry still apply.

Rollback changes no history or release assets: after coordinated approval, keep
or return the native flag to false and stop new native invocations. An already
published immutable version is never rewritten. Re-enabling a legacy path is not
a risk waiver: its current checks still run and may reject ambiguous history.

## Proposed nonpublishing full-size qualification

The explicit manual `native_release_qualification_only=true` input is mutually
exclusive with `native_release=true`; specifying both starts neither route.
It requires no production activation flag. Every existing job explicitly excludes
qualification. The production orchestration and publication queue names remain
unchanged for normal runs; qualification uses a per-run separate queue.
`publication.yml`'s existing read-only findings-gate qualification is unchanged.

This is **not a purely read-only hosted trial**: after separately authorized
configuration and dispatch, the human qualification gate permits local staging
and creation of persistent GitHub SLSA/SPDX attestations for the final-name ISO.
The summary explicitly states that it accepts no findings. The qualification
jobs have contents read and Actions read; only the staging/attestation job has
attestations, artifact-metadata and OIDC write. They receive no App private key
or cache credential. There is no tag/release/cache payload writer, version
mutation, closure restore, rescan, or upload of ISO/parts/release packets.
Only bounded measurement/result receipts are uploaded.

The `release-qualify` purpose and `nonpublishing-release-staging-qualification`
context are distinct from both production risk review and the old gate-only
qualification. First-attempt protected-main identity, exact original/health
producer selection, policy bytes, freshness, signed inventory/boot evidence,
current eligible human reviewer and context digest remain mandatory. Full actual
ISO bytes are snapshotted, signature-verified and compared to inventory and boot,
then passed through the existing splitter and original compressed SBOM staging.
The final-name ISO is a hard-linked private snapshot, not an unverified download.

The qualification-only route deliberately permits **local staging** when the
vulnerability verdict is blocked. It never changes that verdict to clear, adds
risk acceptance, or waives evidence/integrity failures. This is a narrow policy
change requiring explicit code review, not acceptance of current high/critical
findings. Mixed reviewed/qualification flags reject before evidence operations.
Receipts use `nonpublishing-release-qualification-assets`, incompatible with the
production writer even if a separate production approval exists. Direct writer
calls reject the qualification purpose. A later production publication still
needs its own exact approval, evidence and ordinary staging receipt.

The hosted trial would create two final-name attestations using the unchanged
pinned action and release.yml signer. `release:native:verify-qualification`
independently reloads verified evidence and the qualification gate, rehashes the
ISO, and runs the existing read-only final-name provenance/SPDX verifier with
protected policy SHA and exact original SPDX inventory. A late main, approval,
access or freshness change rejects the result. It cannot enter the publisher.
A successful result explicitly remains `authorization:false`,
`publicationReady:false`, `findingsAccepted:false`.

Staging records elapsed monotonic seconds, ISO/staged asset sizes, disk-free
samples at phase boundaries and a bounded 100 ms sampler's minimum observed
free space. These are observations on the shared runner filesystem, **not an
exact peak**, and exclude initial download, tool setup and subsequent attestation
runtime. Keep hosted logs and runner/job timing alongside them. The existing
32 GiB ISO cap, 3x ISO plus 256 MiB headroom check, asset sizes and timeouts are
unchanged. No full-size trial has been run by preparing or testing this patch.

Before any trial: review/merge the exact proposal, wait for fresh signed hosted
CI at that head, confirm exact producer/attempt/source and media retention,
separately approve the findings environment configuration if still absent,
then explicitly approve a hosted invocation including its persistent attestation
writes. Review its complete terminal evidence before considering activation.
This route does not exercise release destination writer-token eligibility,
public tag/release mutation, writable draft visibility, cache writes, or the
production writer's additional asset snapshot disk peak. Those remain separate
qualification/review gaps, not claims made by this nonpublishing trial.
