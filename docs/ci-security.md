# CI, security decisions, and publication

The read-only upstream Gitleaks workflow scans exact incoming PR and merge-queue
ranges. The existing required CI verdict rejects absent, skipped, failed or
cancelled incoming scans, independently of graph routing or evidence reuse.
The `source-security` audit obligation now runs policy and workflow fixtures;
it no longer scans the entire checkout or post-filters findings in Python.
Hosted Nix setup requires 20 GiB of free workspace disk before starting. On a
GitHub-hosted Linux runner only, it may reclaim the fixed unused Android and
.NET SDK directories on that same filesystem, stopping once the reserve is met.
It never deletes workspace data, Nix store paths, caches, artifacts or evidence;
insufficient space still fails closed. This handles runner-image disk variance
without reducing any audit obligation or trusting a retry to land on another
image. Initial and resulting available bytes are logged.

See [the scanner contract](gitleaks-workflow.md) for scope and historical debt.

Maestro and xo-nixpkg release independently. CI produces qualified candidates;
separate protected-main controllers distribute only admitted outputs. This
replaces the earlier report-only publication model. The historical dated security
reviews and orchestration benchmarks describe the earlier implementation.

The checked policy pins the `cl-decider` App integration ID `5384448` and
enables publication only after the initial security baseline has been accepted.
The official XO handoff pins the independently admitted upstream product.
Every rolling and official publication requires current admission and a separate
approval of its exact immutable product.
Shared App keys and client IDs are inherited from organization settings; the
public App ID is also declared as a repository variable in both repositories.

## Contracts and trust

- `ci.yml` audits the repository, qualifies installer media, inventories the
  complete `distribution-inventory` closure, scans current databases, and attests
  `scans.json` and `product.json`. Its signatures establish producer identity;
  they grant no risk acceptance. The inventory includes the appliance, CLI/TUI,
  deployment tools, SBOM generator, and CI toolchain.
- Installer coverage also retains its runtime system, helpers, effective initrd
  sources, and enabled BIOS/EFI/memtest origins in an internal manifest bound to
  the exact ISO. These are qualification roots, not additional public targets.
  The `maestro-distribution-v2` contract requires every manifest root in both the
  authenticated inventory and retained product. Older products remain available
  for historical recovery but need complete fresh coverage before publication.
- Native evidence retains actual installed npm dependencies, native derivation
  and patch metadata, RustSec results, raw scanner observations, database age,
  immutable root NAR hashes, and stable shipped-file exposure bindings. Runtime
  policy expansion requires another decision. Version/store-path changes alone
  do not invalidate accepted equivalent risk; exact applicability must still be
  revalidated.
- `scans.json` binds native reports to the source, trusted producer workflow,
  run/attempt, scan time, and expiry. A rescan may run newer protected scanner
  code (`producer.revision`) over an older immutable product (`revision`).
  Moving an old report never refreshes its timestamps.
- `product.json` binds source, primary and auxiliary output roots/NAR hashes,
  and official asset hashes. It excludes scanner timestamps. Product approval
  covers those exact bytes once, for both rolling and official publication.
- Candidate NARs travel as bounded, hashed binary-cache archive parts through
  Actions artifacts and private digest-addressed `maestro-decisions` GHCR
  packets. Consumers verify provenance, archive members, part hashes, and final
  root NAR hashes before import. Publishers execute no candidate code or builders.
  The evidence registry is not a trusted public substituter; accepted publication
  to Cachix and GitHub remains separately gated.
- `publication.yml` handles Cachix distribution after the
  producer completes. `release.yml` prepares and retains official release bytes;
  `release-publication.yml` reconciles and publishes them after approval.
  Both publishers use the shared FIFO publication queue.

All workflow command bodies call declared devenv tasks. The shared Python
decision core is vendored in both repositories with the same adversarial suite;
it introduces no third automation repository or runtime service. Keep both
copies and their tests synchronized when changing a shared contract.

## Human authority

The repository-scoped Decider App authors content-addressed proposal PRs. Only a
current human member of `closure-labs/super-admins` with maintain/admin access can
approve the exact proposal head. The App-bound `Maintainer decision authority`
check verifies reviews, current membership/permission, changed paths, immutable
packets, and queued content. Governed implementation and policy changes require
the same review boundary. Review submissions, edits, dismissals and PR comments wake
fresh authority checks; comments grant no approval. Successful authority workflow
completion also wakes decision reconciliation, so a late approval can progress
without manually rerunning the earlier collection. Missing PR associations use
bounded live PR discovery. Historical scan packets remain reviewable after expiry;
admission and publication still require fresh evidence. Checks bind the verified
PR head and fail if it moves during evaluation.
The read-only security-audit App stays separate.

Initial approval is required even for an empty finding set. New findings at every
severity, increased severity/CVSS, known exploitation, expanded exposure, or
uncertain runtime policy changes require review. Narrowed supported exposure and
resolved findings carry acceptance forward. Acceptance has no renewal timer.
Explicit rejection, supersession, revocation, and maintainer reaffirmation are
supported. Historical merged provenance never substitutes for current active
human authority. Scanner errors, incomplete coverage, stale evidence, and API
failures cannot be accepted as vulnerability risk.

Rolling candidates need their own `release-product` decision even when their
findings are already accepted. Use the existing **Reconcile maintainer decisions**
manual workflow with the exact completed protected CI `candidate_run` and
`kind=release-product` to prepare that proposal. Review its exact head separately
from source and risk changes. The publisher checks current product authority
again before writes; the `rolling` purpose only selects distribution behavior.

Baseline decisions retain profile security contexts even when their findings
are empty. Installer access, passwords, boot modes, kernel parameters, and
emergency-shell policy are reviewed as a conservative policy projection;
password hashes and changing store identities are excluded from that projection.

Hourly reconciliation proposes uncovered findings and resumes approved work.
Daily audits rescan retained products and compare live repository policy.
One health issue reports audits missing for 36 hours or human decisions pending
for 72 hours. Those thresholds never approve or reject a release.

## XO handoff and recovery

The hosted public consumer can verify the same exact approved roots selected
for recovery: dispatch `consumer-probe.yml` with `proposal_hash` set to the
active accepted product proposal hash. The native `--proposal-hash` selector
rejects absent, rejected or superseded proposals without falling back. It
retains provenance verification, disposable-store downloads, exact NAR hashes
and recursive signature checks. An empty selector preserves the newest
approved-product default for manual and scheduled runs.

The checked `xo-handoff.json` binds an official upstream revision, profile,
output/NAR identity, and immutable `xo-nixpkg-products` evidence packet. Maestro
checks the candidate's original lockfile and handoff policy, the actual imported
XO output, upstream live authority with a separately scoped token, and its own
appliance admission. Upstream approval cannot accept downstream exposure.
Custom packages require explicit `custom` policy and complete local inventory;
they never claim official upstream provenance.

Historical recovery keeps the candidate-source packet as the immutable upstream
product identity. A current protected `xo-handoff.json` may select a refreshed
packet only for the identical repository, revision, channel, store path and NAR
hash. The reader authenticates the original product document and requires the
refreshed product to match in full, including every other profile, root and
asset, before downloading its observations. The refreshed handoff must still
pass independent attestation, current risk and exact-product approval, 48-hour
upstream observation freshness and 48-hour database freshness. A selected
packet's failure blocks recovery; it does not fall back to old observations.

Complete observation documents and the four exact root `handoff-xo-latest.json`,
`handoff-xo-stable.json`, `handoff-xo-rolling.json` and `handoff-libvhdi.json`
envelopes have a 128 MiB metadata bound. Other metadata retains its 16 MiB bound;
descriptor, producer, hash and deadline checks apply to every read.

Daily rescans retain the original product document and release assets byte for
byte. When Actions artifacts expire, recovery resolves the immutable private
decision packet. Ambiguous candidates require explicit selection; lookup and
integrity failures are fatal. Release publication uses a durable SHA-CAS journal
on `automation/publication-journals`, verifies existing remote bytes, and resumes
only missing steps. It never retargets tags or clobbers mismatched assets.

Operator-triggered `deploy-template` remains separate from CD. No XCP-ng pool
credentials or automatic appliance deployment are added.

## Coordinated activation

1. Freeze both repositories' old cache/release writers, drain or cancel pending
   runs, and record exact retained candidates. Merge both replacements while
   publication remains disabled; there is no parallel legacy publisher.
2. Install the Decider App in both repositories. Configure the declared
   `DECIDER_CLIENT`, `DECIDER_KEY`, and public integration identity. Record the
   actual bot login and positive App ID in both checked decision policies and
   corresponding main rulesets. Keep `SECAUDIT_*` administration access read-only.
3. Grant the App only the declared repository capabilities: proposal contents
   and PR writes, authority checks write, actions/administration read, live
   organization membership read, and narrowly scoped queue/health operations.
   Queue tokens are short-lived App tokens; remove the old stored personal token.
4. Require `Maintainer decision authority` from that exact App integration on
   main, alongside each repository's existing CI gate. Keep one PR per merge
   group. Verify the complete reviewed ruleset, no bypass actors, pinned Actions
   allowlist, secret scanning/push protection, and main-only publication/release
   environments. Run the read-only policy audit.
5. Provision private `maestro-decisions` and `xo-nixpkg-decisions` GHCR package
   access for their repository Actions tokens; never clean referenced digests.
   The publisher verifies private visibility before and after packet upload.
   Grant Maestro's runtime reader access to the upstream product packet package.
6. Produce full fresh candidates, approve independent baseline proposal PRs, and
   verify exact-head review, membership removal, dismissal, and merge-queue
   behavior. Existing exception files and machine dispositions do not become
   approved baselines automatically.
7. Activate XO first: merge its reviewed `enabled=true` policy with the live
   rule/environment changes, run its readiness task, and publish an admitted
   upstream product. Keep Maestro publication frozen while configuring that
   product's exact immutable XO handoff and qualifying the downstream candidate.
8. Merge Maestro's reviewed `enabled=true` policy after its baseline approval,
   then run `devenv tasks run ci:decision:readiness`. Exercise an approved release
   and injected partial-publication recovery in each repository before
   unfreezing its scheduled writers. Remove repeated environment
   reviewer prompts only after the App-bound decision path is verified live.

Rollback keeps publication frozen while restoring reviewed, mutually compatible
controllers and policies. It never restores the former ungated cache writer or
report-only release path. Remote policy/App changes and real release publication
are operational activation work, not side effects of a local test run.

## Closure transport performance

Retained Nix closures use Zstandard level 3. Compression changes transport bytes,
not expected product NAR hashes or admission. Import still authenticates the
manifest and verifies the complete bounded archive and exact requested roots.
NAR and ISO artifact uploads use compression level zero to avoid recompressing
already compressed payloads. Existing unchanged-media reuse remains in place.

A local matched-input XO closure export measured 15.51 seconds with Zstandard
versus 1,378.87 seconds with the old XZ default, with 43% more compressed archive
bytes. An actual empty-store restore preserved all 74 path hashes and passed
physical verification without builds. These measurements exclude hosted transfer
time; artifact storage and network cost must be included in hosted comparisons.
Maestro's scanner already processes its combined inventory with one database;
XO's separate profiles now share one fresh verified run-local database. Neither
optimization skips current scanner or runtime contracts.


Publication diagnostic manifests use schema v2: `objects/<sha256>.result.json`
contains the exact canonical full result bytes, while each occurrence retains
its own execution, kind, timing, bounded summary and `resultReference`. Objects
are shared only within one job's artifact, named by job, run and attempt. The
internal reader in `modules/ci/authority/_source/decisions/diagnostic_artifacts.py` accepts v1
and v2, verifies the complete inventory and rejects links, unsafe paths, absent
objects and conflicting hashes. It grants no publication authority.

For offline verification, run `python3
modules/ci/authority/_source/decisions/diagnostics.py --verify <artifact-directory>`. To
attribute an original completed job log, run the same script with `--job-log
<original.log> --job <completed-job.json>`. Log byte categories partition the
original bytes, including timestamps and line endings; timestamps outside a
unique completed step interval remain unattributed. Never substitute a rerun's
log. Runner monitoring remains pinned with its full security coverage; its
current action inputs expose no verbosity control.

Per-execution profiles aggregate fixed gate, packet and transport categories.
Wrapper calls, actual child launches, explicit wrapper retries, captured bytes
and verified immutable-byte reuse have separate fields. Nested gate timings
overlap and must not be summed as job time. Captured bytes exclude unobserved
output on interrupted processes and are not wire traffic; actual HTTP attempts
and wire bytes remain null. Native freshness observations identify their actual
selection, gate, handoff or native-scan boundary and remaining evidence/database
lifetime. A later expired observation alone does not prove stale selection.
The manifest's `logBytes` counts emitted native summaries; whole-job log bytes
are measured separately after the job completes, including final cleanup.

Each execution's profile also contains bounded `requests` attribution. Fixed
labels identify purpose, current versus historical authority, native stage,
innermost gate phase, transport, and cache origin/fallback depth. Only the
innermost phase owns each request: the request rows reconcile exactly to the
existing counters and transport totals, while phase durations remain nested.
No endpoint, query, login, header, argv, store path or credential is retained in
these labels. The raw journal subprocess now has transport measurements, and
candidate selection records its previously unprofiled API wrappers; compare
measurement coverage as well as totals when using older artifacts.

Each cache invocation has a separate inspection identity and counts unique
started paths and fixed response classes for each declared origin. It still
performs its own fresh traversal. No response or authority is cached. Request
rows are capped at 512 plus one explicit overflow row, and inspection records
at 32 per execution; overflow is marked and cannot support detailed attribution
claims. Profiles are limited to 1 MiB by the artifact reader. `requestProfiles`
indexes execution files once rather than summing repeated summary snapshots.
Legacy profiles without request attribution remain readable.

Native Python leaf commands retain bounded `*.stage.json` records indexed by
`nativeStages`. They contain an execution identity, fixed stage, native start
time, monotonic duration and outcome, without changing command stdout or exit
status. The initial record has an unknown outcome and null duration; a killed
process without a completion record stays unknown, and its request profile may
be incomplete. Native durations are not
GitHub step durations and nested child stages must not be summed as whole-job
time. Shell setup, runner monitoring and cleanup remain outside this native
stage coverage. Keep original logs and API responses; missing or ambiguous API
intervals remain unattributed rather than being filled from native records.


The handoff metadata batching experiment is disabled by default through the
non-secret runtime contract `MAESTRO_PACKET_METADATA_BATCH_ENABLED=false`.
Only the existing source-pinned handoff selection can opt into `metadata_many`;
all other singleton readers retain their existing behavior. One verified OCI
manifest and approved packet descriptor bind every requested metadata member,
with the same exact member bounds, hashes and optional producer binding. The
single batch inherits its caller's deadline and retains a 90-second operation
budget. It fetches no closure payloads and caches no authorization result.

Rolling publication offers `metadata_batch_trial=false`. A true manual trial
sets the runtime flag and requires all selected destinations already verified.
The existing cache inspector rejects partial destinations before closure
restore.
Every admission, handoff, pre-write and journal gate remains. Existing manual
candidate and proposal selectors, original producer/signers and freshness limits
are unchanged. The flag supplies no approval or authority.

Non-logged `packet-metadata` diagnostic occurrences retain actual selected member
hashes, original/selected packet identities and fixed operation counts. These
records prove immutable byte identity only. Three selected members require nine
manifest/descriptor/member operations with singleton reads and five with a
batch; historical full-product comparison still reads the original product
separately when the selected observations rotate.

After protected source approval and complete hosted validation, compare a
healthy flag-off execution and verified-only trial with the same controller,
approved product and evidence. Verify identical metadata, original producer and
signer identities, unchanged gates and fresh receipts before promoting the
repository variable. Then run without the trial override and verify current
receipts, an idempotent journal, no duplicate product transfers and a hosted
clean-store consumer. If freshness or human approval is missing, use the existing
maintenance/decision process and keep batching disabled until safe proof exists.

## Public-cache connection-reuse experiment

`MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED=false` is a non-secret runtime
SecretSpec contract. The default retains the existing curl reader. The manual
rolling-publication input `public_cache_transport_trial=false` enables the
experiment only for that selected run and requires verified destinations before
product imports or writes. Neither control supplies approval or authority.

The enabled reader uses the same pinned libcurl engine as the native curl CLI,
through its documented C interface in isolated Python workers. The native
package substitutes the exact store library path; there is no host-library
search or runtime dependency download. Each cache inspection owns at most eight
workers. Every worker retains its own connections only until that inspection
ends. The second inspection starts new workers and performs fresh requests.
Public workers inherit only transport/certificate settings, never GitHub or
Cachix credentials. No GitHub, attestation, registry, handoff or write
operation uses this reader.

The experiment intentionally revises retries. A single budget permits at most
two application-request starts per origin/member read, shared by libcurl's
internal reconnect/HTTP2 recovery and explicit retries. A documented pre-request
callback rejects a third start. The current CLI's “one retry” option does not
bound its separate internal recovery attempts. Preserving those incidental
failure outcomes prevented safe connection reuse; the explicit budget permits
transient recovery while bounding amplification. A dropped connection can now
recover, whereas repeated HTTP2 refused streams exhaust the budget sooner.

Transient connection/refusal, partial-transfer, timeout, empty-reply and
send/receive failures may retry once within that shared budget. HTTP 408, 429,
500, 502, 503, 504, 522 and 524 may retry, with a one-second minimum delay and
Retry-After honored only when it fits. Certificate errors, invalid metadata and
identity conflicts never become accepted through retries. A 404 is not retried;
it retains the existing source-order fallback. The read deadline is 30 seconds
including startup, IPC and retry delays; connect timeout is five seconds and
no retry starts after 25 seconds. The inherited 120-second inspection deadline,
eight active reads, root-first scheduling, path/edge limits, TLS verification,
redirect policy, user agent and 2 MiB response bound remain. Deadline or
cancellation terminates worker process families through the existing bounded
cleanup; no backend fallback occurs during an inspection.

Profiles distinguish logical reads, worker launches, explicit retries, permitted
and denied request starts, successful libcurl connections, decoded metadata
bytes, and captured IPC bytes. Successful-connection counts do not include failed
connects. Start callbacks are not measurements of every HTTP exchange, proxy
handshake or wire attempt. HTTP attempts and wire bytes remain null. Worker
replies that fail or are interrupted increment `unmeasuredReads`; connection and
request-start totals then cover only completed measured replies. Legacy reader
connection counts remain unknown. IPC encoding makes captured bytes unsuitable
as a direct payload-size comparison; decoded metadata bytes and returned bytes
have separate semantics.

All admission, handoff, pre-write and journal gates remain. Tests cover the
intentional retry differences directly. Before promotion, require complete
hosted audit and exact-head review, then a healthy same-controller flag-off/on
pair for the exact approved product and evidence. Require identical returned
metadata and identities, unchanged gate coverage, fresh receipts, independent
inspections and zero product transfers. Separate transient incidents from any
performance comparison. Keep the flag disabled until that proof passes, then
repeat with trial overrides off and verify the exact clean-store consumer.

## Gate-local release verification experiment

`MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED` defaults to `false`. When enabled
for the native release publisher, a single gate owns an in-memory context bound
to repository, verifier source digest, captured protected main commit, policy,
complete ledger and exact product. It validates each decision graph and historical
proposal provenance once. History lookup uses that captured commit. Verified Git
objects and parsed immutable documents are shared only inside this context;
GitHub PR responses and successful live approvals are never cached.

Each beginning/final live-check pass observes the complete pinned team inventory
at both ends. Every active decision still checks exact PR head, current review
state and immutable reviewer identity, individual membership and repository
permissions. Final refresh rereads main, the complete ledger, policy and effective
rules, then rechecks observation/database expiry immediately before success.
A changed binding fails with a bounded `verification-context-*-changed` reason;
a context cannot be used for another gate or write group. Standalone commands,
JSON results and publication receipts retain their interfaces.

Focused fixtures demonstrate identical decisions with fewer requests, historical
validation once per context, and rejection of changed heads, dismissed reviews,
lost membership/permissions, changed main/policy/ledger and mid-gate expiry. These
are deterministic fixture results, not hosted performance measurements. Promotion
requires matched flag-off/on runs with the same controller, product, producer and
evidence, followed by publication and clean-store verification. Keep this flag
disabled until that evidence exists.

## Packet metadata byte reuse experiment

`MAESTRO_PACKET_METADATA_REUSE_ENABLED` defaults to `false`. Metadata-only reads
can reuse the OCI manifest, descriptor and requested members inside the existing
packet cache namespace, keyed by registry/reference, manifest and descriptor
digests, verifier source, run, attempt and job. No closure payload is fetched by
this path. `metadata` retains parsed-document results and `metadata_many` retains
its bounded JSON-member selection and raw-byte results. Existing single-member
reads of input checksums, Cargo inventory and release notes remain supported.

Every hit verifies bytes against their digest and size, reparses manifest and
descriptor bindings, and rechecks the requested producer. Cache operations use
anchored directory descriptors, refuse symlinks/nonregular files, and atomically
publish completed files without overwriting existing entries. Missing entries
may be fetched; corruption and conflicting bindings fail closed. Existing
transport failure classifications and the 90-second metadata deadline remain.
Live approval, independent attestations and health checks are never reused.

Diagnostics retain `metadataCacheHits`, `metadataBytesReused` and
`metadataRegistryOperationsAvoided`, with bounded manifest/descriptor/member
categories. Avoided operations count logical registry commands, not HTTP requests.
The manual `metadata_reuse_trial` requires already-verified destinations. Compare
matched flag-off/on runs before promotion; fixture reductions are not hosted
performance measurements. Leave the repository flag disabled without a safe
matched case.

## Explicit release write-group experiment

`MAESTRO_RELEASE_TRANSACTION_ENABLED` defaults to `false`. The native
`release:reserve` task prepares journal, tag and draft checks before one fresh
downstream/upstream authorization. It then performs the reservation writes and
readbacks in one process. `release:assets` stages bounded upload commands with
fresh authority for every command and retains the recovery hosted-byte pass.
The `release:complete` task performs the final complete hosted-byte download,
prepares its journal update, obtains fresh downstream/upstream authorization,
publishes the draft, verifies publication and records the receipt in the same
group.

A journal conflict, uncertain write acknowledgement or failed readback stops the
group. The controller reads back the remote state without retrying a mutation;
a subsequent invocation prepares state again and obtains fresh authority. An
interrupted upload resumes by verifying existing assets and sending only missing
ones. No plan, file, receipt or successful approval authorizes another group.
Standalone asset and journal commands retain their own checks and default full
publication behavior. `PUBLICATION_STAGE_ONLY=true` selects the explicit staging
leaf used by the composed workflow; it requires an already-reserved tag/draft.

Workflow bodies remain declared devenv task calls. Existing phase-specific token
renewal and partial-draft recovery remain active. Diagnostics attribute the new
native reservation/completion stages and record the effective flag. Fixture
counts establish one fresh authorization per group and per upload command, not
hosted time savings. Promotion still requires a safe matched verified-only case,
then controlled publication and clean-store verification. Leave the flag disabled
when no such matched case is available; never use a published-byte mutation as a
performance experiment.

### Verified-only release transaction trials

The versioned publisher accepts `transaction_trial=disabled` or `enabled` only
with an explicit `candidate_run`. Both modes require an already-verified cache and an existing published GitHub
release with all approved
assets, and unchanged journal proofs. A missing or changed destination fails;
the trial cannot repair it. Trial authority tokens have read-only contents,
pull-request and Actions permissions. Native journal and asset helpers also
reject writes, including asset uploads and draft publication. Development
advancement is skipped.

Compare both modes on the same protected controller, approved product, producer
and evidence with all other flags fixed. Both hosted-byte readbacks, live gates,
upstream handoff checks and fresh receipts still execute. Successful receipt
files do not grant authority. The `default` mode retains the repository's
`MAESTRO_RELEASE_TRANSACTION_ENABLED` setting and normal publication behavior;
trials never change that setting or affect scheduled publishers.

### Publication destinations

Active publication targets are Cachix and GitHub releases. Both rolling and
versioned workflows remove FlakeHub publication, destination checks, receipt
capture and OIDC permissions. The action allowlists exclude `flakehub-push`,
and `release:inspect` accepts only the cache destination.

Existing FlakeHub versions and historical journal receipts are preserved.
Read-only historical destination and receipt readers remain compatible with
retained evidence; they do not publish or grant authority. Keeping the shared
receipt verifier unchanged preserves the identity of existing cache and GitHub
proofs. Upstream FlakeHub input URLs and public binary-cache configuration are
independent of publishing Maestro and retain their existing policy.

## Automatic CI admission for trusted authors

The `Admit trusted pull request CI` workflow approves pending GitHub Actions
execution for both draft and ready PRs authored by `cl-decider[bot]` (pinned
numeric account ID) or a currently active member of the pinned closure-labs
Super Admins team with repository maintain/admin permission. The initiating and
rerun actors must also satisfy that identity policy. An unrelated actor cannot
borrow a trusted author's PR to obtain automatic execution approval.

The protected-main controller reads `ci-admission-policy.json`, authenticates
the repository, allowlisted CI workflow, current open PR head and source
repository, then rereads identity and run/PR bindings immediately before the
run-approval endpoint. It never checks out candidate code, downloads candidate
artifacts, posts PR reviews, dispatches privileged candidate workflows or
requests a merge. Draft-to-ready transitions do not require a review to run CI.
Workflow events handle pending runs; a fifteen-minute scheduled reconciliation
also covers missed events and runs whose approval state appeared later.

Other contributors retain GitHub's existing external-contributor workflow
approval requirement. Missing identity visibility, revoked membership or
permissions, moved heads, changed run attempts and transport failures fail
closed. Ambiguous approval writes are not retried without fresh readback and
identity checks. Human exact-head merge and publication authority are unchanged.

GitHub's [run approval API](https://docs.github.com/en/rest/actions/workflow-runs#approve-a-workflow-run-for-a-fork-pull-request)
approves CI execution only. The App token has Actions write, contents and PR
read, and organization members read; it has no PR-review or contents write grant.

Retired merge-queue event handling is separate from authority approval. When the
collector's exact queue ref returns HTTP 404, the native checker may report
`obsolete` only after authenticating that its main-targeting PR is closed or has
one different live queue ref and candidate. It emits an empty check list and
posts no authority result. A bare 404, conflicting replacement metadata, API
permission/transport errors and invalid collector provenance still block. Live
queue candidates continue to require exact-head review and matching governed
tree contents. Historical failed runs remain intact.
