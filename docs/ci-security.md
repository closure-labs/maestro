# CI, security decisions, and publication

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
  to Cachix, FlakeHub, and GitHub remains separately gated.
- `publication.yml` handles rolling Cachix/FlakeHub distribution after the
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
the same review boundary. The read-only security-audit App stays separate.

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
internal reader in `nix/automation/decisions/diagnostic_artifacts.py` accepts v1
and v2, verifies the complete inventory and rejects links, unsafe paths, absent
objects and conflicting hashes. It grants no publication authority.

For offline verification, run `python3
nix/automation/decisions/diagnostics.py --verify <artifact-directory>`. To
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
restore, and the existing FlakeHub inspector rejects them before publication.
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
