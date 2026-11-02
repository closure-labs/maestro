<!-- SPDX-License-Identifier: Apache-2.0 -->
# Draft: standard review and native evidence for Maestro publication

Status: local design for approval, based on main
`4c4aff35d2223c6f03447a32621dd2d36999b26c` (2026-11-02).
This document changes no executable policy, workflow, ruleset, permission,
publication setting or historical decision. Preparing it does not authorize
publishing a policy-changing PR, running a publication, or accepting findings.

## Decision and immediate scope

Replace historical-ledger admission with standard GitHub source review plus
fresh, authenticated native build/security evidence. Reuse the existing native
security verdict and source-bound policy file. Keep immutable historical records
in Git; stop treating their supersession graph as a prerequisite for new builds.
Do not choose one leaf, copy old acceptance into a baseline, create a repair
record, or add another recovery controller.

The smallest credible first implementation changes **publication selection and
its consumers**, while retaining the already-working main CI producer. Replacing
all CI at the same time would mix an authority change with test-coverage and
artifact-contract changes. Ordinary CI consolidation follows the consumer cutover,
with an explicit deletion list rather than a permanent parallel workflow.

The current blocker is precisely two accepted leaves (`811bec34…`, `fc566809…`)
superseding `baf94a59…`; both contain 346 equal findings/contexts but different
packet identities. Main has 15 ledger documents totaling 150,803,612 plain JSON
bytes. Publisher 41385290531 captured 207,968,710 subprocess-response bytes over
20 GETs and stopped before any gate/destination operation. Captured bytes are
not wire traffic. Main qualification 41379990640 succeeded; technical validation
and historical risk admission are separate today.

Repository evidence: `modules/ci/authority/_source/decision-retained.py:70`,
`modules/ci/authority/_source/decisions/common.py:232`,
`modules/ci/authority/_source/decisions/security_decisions.py:357`,
`modules/ci/security/_source/security-verdict.py`, and
`modules/ci/security/_source/security-native-check.py`.

## Proposed authority and security contract — not active

1. Require one eligible human review for **every PR, including Dependabot**;
   dismiss stale reviews and require approval of the latest reviewable push.
   Protect the reviewer definition and publication/security workflows with
   CODEOWNERS. Retain the merge queue and existing CI/CodeQL App bindings.
2. Only a completed, successful, protected-main producer for the exact selected
   source revision may supply publication data. Pin repository, workflow, event,
   source ref/digest, run ID, run attempt, artifact digest and signer identity.
   PR/merge-group evidence cannot authorize publication. The privileged job
   checks out trusted main; downloaded artifacts are data, never controller code.
3. Preserve complete distribution coverage (`maestro-distribution-v2`), runtime
   contexts, exact planned roots/NAR identities, SBOM/checksum identities, pinned
   upstream XO supply evidence, actual installer boot and native scanner health.
   Preserve evidence age <=24h and database age <=48h, reject future timestamps,
   and keep current DB update/probe/RustSec requirements. Provenance is not a
   claim that vulnerabilities are acceptable.
4. Publication must enforce the existing native `security-verdict.evaluate`
   result: unresolved **high, critical or unknown/unscored** findings block.
   CI may retain its current report/observation behavior so remediation PRs can
   be reviewed. `mode: report` must never bypass the publication verdict.
   The revised user policy permits explicit independent human acceptance of
   specific high/critical risk. Routine code approval is insufficient. The staged
   implementation uses one dedicated standard-review artifact, exact finding and
   product/evidence/policy scope, a clearly labeled dedicated findings-risk PR approval,
   revocation checks and proposed maximum-30-day expiry. Source-policy exceptions
   remain empty; this replaces their waiver route rather than adding a second
   active waiver store. See [the reviewed activation proposal](native-cutover/activation.md)
   for the complete mechanism and expiry/revalidation choices still to confirm.

5. **No grandfathering of the 346 findings.** Before activation, show a fresh
   severity/applicability report from the exact tested source. If blocking
   findings remain, public writes stay disabled until remediation or separately
   approved exact exceptions. Approving this design is not that approval.
6. Publish only the existing four Cachix roots: `maestro-menu`, `maestroctl`,
   `deploy-template`, `sbomnix`, with their required runtime closures. Preserve
   the existing cache URLs/keys, recursive NAR/signature verification and cold
   consumer checks. No whole-store/watch-all upload, new cache, trust key, or
   upstream XO publication. Cache signatures identify the trusted pusher/NAR;
   they do not grant human risk acceptance.
7. Serial publication uses one native GitHub concurrency group. Check source,
   policy, evidence freshness and destination identities immediately before each
   write group; reject observed main/policy drift. Do not rebuild or rescan
   unchanged immutable inventories unnecessarily. A scan refresh consumes the
   authenticated SBOM, not a downloaded closure. No cross-service atomicity or
   guarantee against a ref moving after the last read is claimed.

## Exact standard-review replacement

Live ruleset **20919039**, “Protect main with merge queue and CI verdict”,
currently has approving-review count 0, stale dismissal false, code-owner review
false and last-push approval false. Required thread resolution, merge-only PRs,
non-fast-forward/deletion protection and merge queue are enabled. Preserve these.

Retain exactly these check/App bindings through the initial cutover:

| Check | Integration ID |
| --- | ---: |
| Required CI verdict | 15368 (GitHub Actions) |
| Analyze (actions) | 15368 |
| Analyze (javascript-typescript) | 15368 |
| Analyze (python) | 15368 |
| Analyze (rust) | 15368 |

The eventual separately approved settings delta is: review count 0 -> 1,
`dismiss_stale_reviews_on_push=true`, `require_last_push_approval=true`,
`require_code_owner_review=true`; remove only `Maintainer decision authority`
(integration 5384448) **after** standard review is verified effective. Do not
change queue parameters, other required checks/App sources, bypass actors,
merge methods or thread-resolution behavior. Never select “any source”.

Proposed CODEOWNERS initially: `* @declarative-dale`, covering CODEOWNERS itself.
Live readback found `closure-labs/super-admins` ID 20196962, privacy `closed`, one
member `declarative-dale` (52590374), but no direct repository team binding.
GitHub requires a CODEOWNERS team to have repository write access itself; do not
silently grant that access. The named-owner proposal avoids a permission grant.
This still requires explicit approval before adding/enforcing it. Dale-authored
PRs cannot be self-approved: identify a second eligible human before such PRs
need merging, or leave them blocked. Do not add a bot or a bypass as a substitute.

This is GitHub's review/diff model, not the old custom numeric-ID, Super Admin
membership and maintain/admin recheck before every public write. Future reviewer
changes require a reviewed CODEOWNERS change. Native review does not authenticate
per-finding acceptance unless the PR explicitly changes the exact policy entry.

## Security-guarantee delta requiring approval

| Guarantee | Proposed treatment |
| --- | --- |
| Pinned XO, appliance/TUI/wrappers, VM/service/TLS/storage/privilege tests and ISO boot | Retained; no host configuration or input-pin change. |
| Required checks, CodeQL/Gitleaks, merge queue and unprivileged PR execution | Retained; stable verdict still fails missing/failed required obligations. |
| Build provenance, exact root/NAR/ISO/SBOM identity, complete coverage and fresh healthy scans | Retained using existing native data and standard GitHub attestations. |
| Four-root cache scope, signed public-cache trust and independent cold readback | Retained; no trust/credential expansion. |
| Independent human approval of the current source change | Replaced by standard required code-owner review, stale dismissal and last-push approval; Dependabot included. |
| Live custom Super Admin ID/membership/role recheck at each publication write | Removed. GitHub review/CODEOWNERS/environment controls replace it; mid-run revocation is not independently replayed. |
| Every new/worsened finding, including low/medium, needs exact ledger acceptance | Removed. Proposed native threshold blocks high/critical/unknown; lower severities remain reported for review. This is an explicit security-policy change. |
| Human exceptions for blocking findings | Existing source-bound policy records, expiry <=30 days, reviewed as ordinary protected source PRs. No exceptions imported or accepted by this draft. |
| Global supersession/revocation DAG, historical review replay, OCI decision packets and exact packet ancestry | Retired for new publication; immutable Git history remains. No “newest” leaf choice or equivalent replay guarantee. |
| Explicit product-by-product release acceptance separate from code review | Replaced by standard manual versioned-release approval of exact prepared bytes. Routine cache publication relies on reviewed main plus mandatory native policy. |
| Custom cross-service reservation/completion journals and recovery transactions | Retired. Use draft releases, immutable digests and read-before-write; partial cache/release effects can remain after failure and must be inspected before retry. |
| Complete historical offline distribution restore from decision packets | Kept during consumer migration; later retired after no consumer needs it. Selected cache closures and versioned ISO/SBOM assets remain retrievable. |
| Same-candidate duplicate graph/reference validation and historical equivalence controller | Removed only after the twenty-obligation mapping and required boot pass on the replacement producer; no fake green substitutes. |

Current baseline is stricter about explicit approval of all finding identities;
standard provenance and a severity threshold do not preserve that property.
Likewise, standard concurrency is not a distributed transaction. These losses
must be accepted explicitly, not described as performance-only refactoring.

## Native target DAG and credentials

Initial publication cutover reuses `ci.yml`'s successful signed qualification:

`protected main CI -> verify native artifacts/policy -> selected cache upload -> cold scoped cache probe`

Versioned releases use standard jobs:

`manual exact source_run/version -> prepare immutable draft assets -> release-environment human approval -> publish draft`

Keep the existing versioned filenames, checksum format and split-ISO helper:
current ISO size exceeds the existing 2-GiB asset contract. Verify complete part
sets and reconstructed digest; never overwrite different bytes under a version.
A GitHub draft release is staging, not the former immutable product-decision
record. Existing published versions/records are not rewritten or deleted.

After the CI-only retirement stage, `ci.yml` has `validate`, `attest`, `verdict`
plus the existing reusable secret scan. `validate` runs ordinary flake checks,
explicit appliance/ISO/pinned XO/menu/CLI/deployment-wrapper/sbomnix builds,
one inventory generation, one fresh scan and one required ISO boot on the same
hosted store. Runtime VM and installer boot are distinct coverage, not duplicates.
`attest` has only the OIDC/attestation permissions it needs; PRs get no signing or
publication secrets. `verdict` keeps the existing required name/App and rejects
required-job skips/failures. CodeQL remains its existing separate workflow.

The privileged cache/release writer stays separate from builds and executes no
candidate NAR. Initially consume the unchanged final native report/transport;
only after consumer migration replace full transport with one authenticated
handoff of the four selected cache closures. Preserve all 60-root coverage claims
in the signed inventory (60 at this baseline; future candidates cover their
complete evaluated set, not a constant count). Do not equate four uploaded roots
with full distribution coverage. Nix paths can be input-addressed: retain NAR hashes and signatures,
not path-name-only trust. Never rebuild in a credentialed writer.

Use current Cachix write credentials only in the main cache writer and existing
release environment for versioned release approval. Verify that environment's
reviewer/self-review protections before activation; its mere existence is not
proof of approval enforcement. Standard scoped `github.token` handles release
assets/attestations. The publisher should no longer need a Decider private key,
organization membership reader, GHCR decision-packet writer or branch/PR writer.
Keep Decider credentials where still needed for lock-update PR authorship; do
not delete global contracts blindly. No new permission/environment is approved
by this design. Preserve sole independent human review and no bypasses.

## Consumer migration and exact implementation/deletion order

| Owner/files today | Replacement and deletion boundary |
| --- | --- |
| `.github/workflows/publication.yml`; `decision-retained.py`; `decisions/publication*.py`, `verification_context.py` | Native artifact preparation verifies exact successful main run/attempt and current policy. No ledger or pending-proposal selector. Replace admission calls before enabling writes; delete historical selector/controller after all callers migrate. |
| `.github/workflows/release.yml`, `release-publication.yml`, `release-continuation.yml`; `modules/release/publication/_source/release-request*`, `release-manager.sh`, `release-reservation.sh`, `release-completion*`, `publication-journal*` | One manual exact-run/version workflow with draft staging and protected human publication. Keep pure `release-split.sh`, version/notes/checksum/asset validators; retire request callbacks, journals, reservation and continuation consumers together. |
| `modules/features/installer/_source/download-installer.sh`, `verify-state.sh`, `verify-inventory.sh`; XCP-ng `deploy-template.sh` | Keep protected-main run/attempt, checksum/state and attestation verification, no silent local-build fallback. Preserve current state/artifact contract initially. Later consume direct native successful-main artifact identity instead of origin indirection; update fixtures before removing producers. |
| `.github/workflows/consumer-probe.yml`; `modules/release/consumer/_source/consumer-probe.py` | Select an exact authenticated native product/run, then retain isolated empty-store, builder-disabled, recursive bytes/signature/cache-scope probe. Remove ledger/accepted-release selection and its `max(runId)` authority rule. Never inspect unrelated historical candidates. |
| `.github/workflows/security.yml` | Keep fresh Grype/RustSec scanning against authenticated immutable SBOMs; no closure download for advisory refresh. Remove retained-official proposal enumeration/reconciliation hooks after native release consumers migrate. |
| `modules/ci/authority/_source/decision-candidate.py`; signing/product consumers | Keep the technical `product.json`/`scans.json` builder under native inventory ownership before deleting `ci:decision:candidate`; these reports are not ledger decisions. |
| `modules/ci/security/_source/security-native-check.py`, `security-normalize.py`; inventory `security-inventory.py`; their `_lib/commands.nix` | Reuse health/coverage/context checks and exact finding normalization. Move only live pure fingerprint/normalization helpers out of `authority/_source/decisions`; remove ledger/config/App dependencies from native verification. Do not introduce a general policy/controller framework. |
| `modules/ci/graph/_source/distribution-cache.py`; installer `qualification-restore.py`, `_lib/commands.nix`; development cache doctor | Preserve bounded archive/NAR verification, streaming copy diagnostics and timeouts wherever transport remains. Move the small live operations/cache-identity helpers to their native owner before deleting authority imports. No unreviewed transport/timeout/compression change. |
| `.github/workflows/decisions.yml`, `decision-authority.yml`, `decision-events.yml`, `decision-packet-inspection.yml`, `release-continuation.yml`, `ci-admission.yml`, `queue-automation.yml` | Retire after consumers/settings migrate. Use ordinary same-repo PR/Dependabot CI and native queue/auto-merge controls; do not recreate a bot enqueue controller or bypass the unresolved enqueue permission denial. Inspector/recovery remain paused. |
| `.github/workflows/ci.yml`, `flake-checks.yml`; `modules/ci/graph/*` | After one exact-source parity cycle, promote the ordinary implementation in place under `Required CI verdict`; delete the temporary parallel workflow, routing/retained/comparison/equivalence controllers and unused graph commands/checks. |
| `secretspec.toml`, `modules/ci/authority/_source/github/main-ruleset.json`, policy-drift fixtures, command/task/package declarations | Remove unused publication credentials/flags and update the desired review contract only in the approved activation patch. Keep native drift checks and every still-used credential. |
| `automation/decisions/**` | Preserve all 15 records unchanged as historical audit data; remove runtime reads, not history. No new reconciliation record. |

A reference search must also cover `MAESTRO_DECISION_CORE`,
`MAESTRO_FINGERPRINTS_CORE`, `PUBLICATION_DESTINATIONS_SOURCE`,
`MAESTRO_DECISIONS_SOURCE`, `release:*`, `ci:decision:*`, documentation and all
import-tree/flake task declarations. Deleting the directory first would break
native inventory, normalization, consumer probes and cache transport.

## Account for every current validation obligation

The source of truth is `modules/ci/graph/_lib/plans.json` (20 targets). Preserve
all product/security assertions. Retire only assertions about deleted controllers
and replace workflow/consumer contracts at the native boundary.

| Current target suffix | Treatment after producer retirement |
| --- | --- |
| metadata | Retain product metadata assertions. |
| maestro-ci-repository-audit | Retain underlying source/product assertions; remove redundant outer orchestration wrapper after full ordinary realization. |
| maestroctl | Retain CLI build/tests. |
| flake-plan-runner | Retire wrapper-specific tests when no job uses the runner; direct Nix check failure propagation replaces it. |
| eval-smoke | Retain flake/config evaluation. |
| workflow-policy | Replace retired workflow-name/graph assertions; retain permission, trusted-source, merge_group and required-verdict checks. |
| devenv-contract | Retain native task declarations and remove deleted command references. |
| shell-lint | Retain for every live shell command. |
| automation-fixtures | Keep input-update/PR safety; remove deleted reconciliation/queue machinery tests only with their consumers. |
| qualification-input-fixtures | Retain complete product input/coverage checks; remove historical admission-context controller assertions. |
| release-fixtures | Retain version, split parts, checksums, refusal to overwrite different assets and consumer checks; retire request/journal/transaction tests with deleted code. |
| secretspec-contract | Retain current runtime secret scope and no-secret-in-Nix checks; remove only unused contracts. |
| operator-fixtures | Retain CLI/TUI/wrapper/operator/deployment behavior. |
| repository-policy | Retain source/layout/appliance invariants; update obsolete controller references. |
| configuration | Retain sole Maestro/XCP-ng/NixOS policy assertions. |
| ci-plan-contract | Retire custom graph planning; replace with direct DAG, exact native artifact and always-running verdict negative fixtures. |
| security-fixtures | Keep scanner health/freshness, native normalization/context/applicability, provenance, NAR/archive, process bounds and cold-consumer tests. Retire ledger/proposal/packet/recovery tests only with that code. Keep XO storage/file-restore fixture dependencies. |
| runtime-security | Retain the real NixOS service/TLS/management/storage/privilege VM. |
| packer-policy | Retain Packer/template validation; no production deployment during CI. |
| source-security | Retain source security/Gitleaks assertions and the existing byte-bound current-change scan. |

When graph planning retires, bind consumers directly to source/run/attempt and
the attested native product/root-input manifest digest. Version the technical
contract and update producer/consumer fixtures together before removing legacy
verification; do not keep a hidden planner to manufacture obsolete fields.

No obligation gets a stub success result. The table is not hosted parity proof.
ISO boot is an additional essential obligation, even though it is not one of the
20 graph validation targets. Pinned XO integration, compiled menu, native app
wrappers, file-restore/storage fixtures and signing/cache trust remain required.

## Three bounded stages and exit criteria

**1. Prepare native consumers, no activation.** After permission to publish an
implementation draft, add the smallest native artifact-preparation leaf and
fixtures, migrate consumer input interfaces behind inactive wiring, and retain
all current required gates/publishers. No new scheduled controller or permanent
parallel full build. Existing hosted PR CI runs the focused fixtures. Authorize
one read-only exact-main prepare comparison only when its workflow/code is
reviewed; no write credential is available. Compare product/root/NAR/ISO hashes,
10 bound inventory/checksum documents, contexts, coverage, boot disposition,
24h/48h freshness, and exact run/attempt/signer. Old history remains blocking
publication. Exit: native consumers can validate that same evidence without
ledger/network-history access, and failure cases fail closed.

**2. Explicit authority/publication activation.** A separately approved patch and
settings operation install/enforce standard review first while the old authority
check still remains. Verify one approval cannot survive a changed head, bots or
self-review cannot satisfy CODEOWNERS, and Dependabot follows the same rule.
Only then remove the old authority check, switch all publication/consumer entry
points to native evidence and disable old scheduled/continuation writers in the
same coordinated window. Confirm no in-flight writer/queue candidate will race
the transition. Public writes remain off until the fresh severity report,
mandatory native verdict, provenance and destination readback pass. Versioned
release approval remains an explicit human action. Exit: one approved exact
qualification has native, scoped, verified publication/consumer behavior, with
no historical selector, journal or repair dispatch. No risk entry is created as
part of this stage.

**3. Delete the obsolete machinery and duplicate CI.** On one agreed matching
PR/merge-group/main cycle, validate the ordinary producer plus essential boot,
complete the 20-row disposition above and exercise downstream consumer fixtures.
Then replace `ci.yml` in place, delete `flake-checks.yml` in the same cutover,
remove dead authority/packet/graph/continuation code and unused credentials,
and stop complete-closure transport only after its last consumer migrates.
Keep an immutable manifest with complete inventory coverage and only the
necessary selected-root handoff. Exit: reference search finds no live ledger or
retired workflow/task imports; no extra comparison job remains permanently.
If parity fails, fix the named gap or remove the temporary trial—do not extend
it indefinitely or weaken an assertion to obtain a green result.

## Required tests and failure cases

Local work is bounded fixtures only (<512 MiB); full flake/VM/ISO work is hosted
and needs the applicable implementation/trial authorization. This document
alone does not dispatch it.

- Reject wrong repo/workflow/event/ref, PR/fork evidence, missing/expired or
  substituted artifact, wrong source SHA/run/attempt, signer mismatch, invalid
  attestation, self-hosted signer, incomplete root/NAR/coverage/context or swapped
  SBOM/checksum/ISO. Distinguish GitHub PR head from the tested merge SHA.
- Reject failed/skipped required checks, fake boot disposition, missing boot log,
  stale/future observation, stale/invalid DB, failed update/probe, missing RustSec
  revision and unscored findings. An ordinary ISO build is not a boot test.
- Native `evaluate` must block unresolved high/critical/unknown publication even
  with observation `mode: report`; low/medium treatment must be visible. Reject
  changed finding identity, expired/future/over-30-day exception, missing
  owner/rationale/evidence. Empty policy must never import historical waivers.
- Mutating either historical leaf or adding more leaves must not alter native
  technical selection; a test must assert zero ledger/OCI/PR-history accesses.
  This demonstrates retirement, not implicit acceptance of those records.
- Mutate current main/policy between prepare and write; no destination write.
  Fail destination digest mismatch, duplicate version with different bytes,
  missing/extra ISO part, bad cache signature/NAR or changed trusted key/scope.
- Cold probe uses an empty store, builders disabled and the same approved
  URLs/keys. Verify only four approved roots/dependencies; no global cache watch.
- Check privileges: no secrets/public writes on PR/merge_group or read-only
  prepare; writer does not execute candidate code; no retired App member/admin,
  packet-registry or repository mutation permission silently survives.
- Keep real subprocess output/exit134/signal/timeout/receipt-bound tests, native
  product tests, actual boot, and focused consumer tests. Do not merely mock
  subprocess argument construction or mirror implementation conditionals.
- Exercise interrupted upload: inspect existing destination digests before retry,
  preserve immutable published bytes, and report partial completion honestly.
  No cross-service rollback guarantee is substituted by a new controller.

## Rollback and approval boundaries

The preparation stage has no public-write path, so rollback is an ordinary source
revert. For activation, retain the prior workflow/policy/settings snapshot and
an explicit stop-publication procedure. On failure, disable/hold new writers,
verify in-flight runs and destination outcomes, then restore the prior required
check/workflow through normal review. Keep the stronger standard review unless
separately approved to change it. Reverting code cannot retract downloaded
Cachix paths or published release assets; do not delete/overwrite them as an
implicit rollback. The old ledger would still be ambiguous, so reverting may
restore a safely blocked publisher rather than a working one.

Before **publishing an implementation PR**, approve its scope after reviewing
this guarantee delta. Before **actual cutover**, obtain approval naming the
exact implementation head and hosted qualification/consumer run IDs and stating:

> Approve replacing historical ledger/packet admission with the specified native
> high/critical/unknown publication verdict and standard human CODEOWNERS review,
> including Dependabot. Approve the listed ruleset 20919039 review changes and
> removal of only App check 5384448 after review enforcement is verified, the
> explicit publisher/consumer migration and controller deletion, and the stated
> loss of historical acceptance/revocation replay and cross-service journals.
> Keep current CI/CodeQL App bindings, queue, pins, cache trust/scope and
> technical freshness/coverage/boot checks. Do not import/accept the 346 findings.
> Public writes stay disabled until native policy passes. Activation approval
> must specify writer credentials/environment protections and whether automatic
> four-root Cachix publication from future qualifying main runs is authorized.
> Versioned releases still require exact source/version and human release approval;
> any risk exception needs its own explicit reviewed approval.

Do not request blanket permission to “simplify security”. Resolve the named
reviewer/own-PR issue and verify release-environment protections before that
approval. This draft gives no approval to change settings, accept risk, merge,
enqueue, deploy, run recovery/inspection or publish production data.

## Standard mechanisms and references

- [GitHub protected branches/reviews and App-bound checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub CODEOWNERS eligibility and self-protection](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [GitHub artifact attestation generation/verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [Cachix selected runtime closure uploads](https://docs.cachix.org/pushing)
- [Cachix signing/authentication boundaries](https://docs.cachix.org/security)

These mechanisms establish specific review, producer and byte-integrity claims;
they do not recreate the retired all-finding human-acceptance graph.

## Stage-one implementation in this draft

`ci:native:prepare` / `maestro-ci-native-prepare` is an unused, read-only leaf.
No workflow or active publisher calls it. It emits `authorization: false`,
`publicationReady: false`, `riskAcceptanceEvaluated: false`, and does not evaluate
or change the currently active publication/security policy. Healthy findings may
be observed without accepting them. Existing gates still decide publication.

For a later separately approved read-only trial, explicitly stage the existing
main-run native reports in one local directory:

- `product.json`, `scans.json`, `security-result.json` from the native report;
- `ci-result.json` from the complete result artifact;
- `inventory-binding/manifest.json`, renamed to `inventory-binding.json`;
- the five inventory documents and their five `.sha256` files from `maestro-evidence`.

Invoke the packaged command with `--directory DIRECTORY --run RUN_ID --attempt N
--revision FULL_MAIN_SHA`. There is no latest-run selector, download, cache/store
import, registry access, decision operation, PR action or public-write option.
It freezes the expected files in a private temporary directory, verifies product,
scan and result attestations against the exact main source and signer, checks
current main before/after preparation, and binds the ten document hashes,
complete native root/NAR metadata and the actual boot disposition. Non-CI
producers remain unsupported. For `verified-retained` boot, also supply
`original-ci-result.json` and `original-boot.log`, plus all three explicit flags:
`--boot-origin-run RUN --boot-origin-attempt N --boot-origin-revision FULL_SHA`.
There is no origin discovery, latest-attempt selection or recursive proof replay.
The original successful main CI run/attempt and its attestation must match those
inputs, the original result must declare directly executed boot, and its exact
log, ISO, media-input and verifier digests must match. Different graph digests
between original and current source are expected; each boot binds its own graph.
Current source, policy, scanner health/freshness and complete root coverage still
apply. Retained boot remains labelled `verified-retained`; it is not a new VM run.

Bounds: `scans.json` and `security-result.json` <=64 MiB/file; other JSON
<=16 MiB/file; inventory documents <=64 MiB/file; original boot log <=4 MiB;
total snapshot <=256 MiB. Strict duplicate-key/nonfinite JSON parsing is retained.
Parse the two large reports sequentially and compare incremental canonical
hashes, avoiding two retained native objects or a report-sized serialization.
Python validation has a 512 MiB address-space limit, restored before external
GitHub verification (the Go verifier reserves more virtual address space).
Command stdout/stderr <=4 MiB each, per-command timeout 90 seconds and
invocation budget 300 seconds with existing process cleanup. Duplicate JSON keys,
nonregular/symlink inputs, changed files and invalid identities fail closed.
The receipt describes verified technical metadata, not cold verified NAR/ISO
bytes or an admission capability. It cannot authorize a later publisher to use
mutable originals; later consumers must reverify their actual bytes. The old
full transport/consumer contracts and all twenty obligations remain untouched.


## Inactive compatibility preparation (2026-11-02)

Read-only staging of main CI `41416585167/1`, source
`64922546a9f759702e7be31deff62a883974790b`, established three real gaps:
55,706,156-byte scans and 52,521,292-byte native reports exceeded the original
16 MiB limit; boot was retained from `41379990640/1`; reuse inventory had no local
ISO and recorded `isoSha256: null`. The sequential parsing/normalization probe
on those reports used 160,300 KiB peak RSS under a 512 MiB limit and produced
346 normalized findings / 60 roots. This was not a live preparation trial or
attestation verification. Fixtures use generated data, not production reports.

The result producer now adds an explicit `inventoryIsoBinding` object:
`{schemaVersion: 1, producer: CURRENT_PRODUCER, inventorySha256: MANIFEST_SHA256,
isoSha256: BOOT_VERIFIED_ISO_SHA256}`. It is emitted only after the existing boot
result digest, graph/media/verifier policy and complete validation checks pass.
The boot job already verifies/hashes the retained ISO, so no extra ISO transfer,
export or boot is introduced. The earlier inventory artifact remains immutable.
The consumer requires this exact producer/digest binding when retained inventory
has a null ISO field, plus the separately authenticated original executed-boot
proof. It does not silently treat null as sufficient evidence or claim local
ISO/NAR-byte verification. Non-null inventory ISO must still match exactly.

This is an additive technical result field, not a change to admission, severity
policy, required checks, signer trust, permissions or publication wiring. Existing
consumers retain their current fields and gates; the new consumer stays unused.
Old run `41416585167/1` lacks this explicit new binding and must still reject.
No artifact may be rewritten/backfilled. After separate publication/review/merge,
a fresh exact-main qualification would be needed before any separately authorized
read-only preparation trial. The actual security cutover remains separately
approved under the guarantee delta above.
