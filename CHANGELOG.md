<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to published Maestro releases are documented here. This
project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) beginning with
version 1.1.0. Earlier development records are preserved below and may not
correspond to published GitHub tags.

## [Unreleased]

### Changed

- Bind exact product derivation recipes into qualification fingerprints while
  retaining existing output-path fields and historical state/receipt readers.

- Keep installer content realization and transport in the installer phase;
  preserve complete Nix source contexts for copied origins and verify that
  inventory receives every attributed root.

- Add a disabled-by-default graph-to-native routing handoff with bound per-job
  decisions, conservative state regeneration, immutable dispatch comparison
  bases and exact scheduling-mode checks at signing and the required verdict.

- Separate canonical evidence bindings from scheduler implementation so planning
  changes do not invalidate retained boot verification. Verify scheduler and
  binding-policy dependency propagation in hosted mutation checks.

- Limit CI closure transport to selected, inventory-covered outputs so signed
  cross-run restores do not depend on undistributed secondary build outputs.

- Generate the flake with pinned flake-file and flake-parts while retaining
  Den v0.16.0 and the single `maestro` appliance. Colocate policy, packages,
  operator/installer/Packer sources and validation with feature owners.
- Export `lib.ciGraph.x86_64-linux` with evaluated derivation/output identities
  and add graph inspection alongside the existing CI plan interfaces.
- Split repository audit, appliance, ISO, boot, inventory, scanning and evidence
  verification into explicit jobs with digest-bound exact-output transport.
  Keep all twenty validation obligations, live release authority and historical
  evidence readers. Graph scheduling remains in shadow mode pending hosted
  comparison; equal derivations alone never authorize skipping a test.

- Compare the complete audit against independent, exact graph-derived
  realizations on the same candidate and workflow attempt. Bind comparison
  receipts into release evidence and the required verdict while selective
  scheduling remains disabled. Narrow qualification and boot-verifier sources
  to their actual dependencies.

- Remove obsolete CLI staging pathspecs after source relocation, and consolidate
  repeated operator fixtures under their canonical repository audit owners.

- Automatically admit pending CI for draft and ready PRs from the pinned Decider
  bot or live Super Admins, without granting review, merge or publication authority.

- Remove rolling and versioned FlakeHub publication, its workflow OIDC
  permissions and action allowance. Publication now targets Cachix and GitHub;
  historical receipts and published versions remain readable.

- Add explicit verified-only off/on trials for release write grouping. Trials
  require a selected producer, use read-only authority tokens and reject changes
  to published destinations or journals while retaining fresh authorization.

- Add disabled-by-default gate-local release verification reuse. Immutable
  decision graphs and proposal documents can be shared within one gate while
  final reviews, membership, permissions, policy and evidence expiry remain live.

- Add disabled-by-default job-local reuse of authenticated packet metadata bytes.
  Revalidate cached hashes and producer bindings while retaining live authority,
  attestation and freshness checks at every existing publication boundary.

- Add disabled-by-default native release reservation and completion tasks that
  group adjacent writes under fresh authority. Keep upload-batch checks, both
  hosted-byte readbacks and scoped token renewal.

### Fixed

- Capture the expected unknown-event rejection in CI routing fixtures so passing
  negative tests do not emit misleading live schema-error annotations.

- Group small release assets into bounded uploads with fresh authority checks
  per batch and before publication. Renew scoped tokens before asset and
  completion work, and retain safe HTTP status diagnostics for authority failures.

- Target the newest official version during automatic release discovery when an
  older approved release remains unfinished. Preserve explicit historical
  recovery, reject conflicting products for the same version, and avoid falling
  back to older releases when the newest is suppressed.

## [3.1.0] - 2026-10-25

### Added

- Add a hosted clean-store consumer that verifies published appliance roots,
  downloaded bytes and signatures through the pinned public caches. Operators
  can select an exact accepted product for recovery verification.
- Add publication summaries and credential-safe diagnostics for successful and
  failed runs. Full results are stored once per digest while every execution
  remains traceable; both legacy and compact diagnostic artifacts can be verified.
- Add measurements for publication stages, native gates, packet reads, retries,
  captured bytes and health expiry. HTTP attempts and wire bytes remain unknown
  where the transport cannot measure them reliably.
- Add controlled trials for read-only publication preflight, handoff metadata
  batching and public-cache connection reuse. Verified-only trials prevent
  product imports and destination writes while preserving live admission checks.
- Add decision-only evidence reuse and shadow eligibility checks behind a
  disabled runtime setting. Exact product identities, fresh observations and
  current human authorization remain required.
- Add an opt-in Devenv keyring prompt and read-only cache permission diagnostic.
  Optional credentials use the explicit runtime SecretSpec profile and stay out
  of Nix evaluation and the store.

### Changed

- Inspect admitted products and handoff metadata before transferring closures.
  Reuse verified immutable packet and decision bytes within a job while repeating
  live authorization checks at every required boundary.
- Batch handoff metadata reads through one validated manifest and descriptor,
  and support connection reuse within a public-cache inspection. Connection
  reuse shares a bounded two-request retry budget with its fallback.
- Reconcile publication destinations before uploading and verify remote
  identities before recording completion, retaining compatible receipt journals.
- Reuse unchanged installer qualification in merge queues. Changed media and
  forced or scheduled qualification still receive fresh builds.
- Separate scan inventory and advisory database work from fresh observations to
  avoid repeating unchanged work.
- Update the native Devenv toolchain to 2.4.0 with synchronized lockfiles. The
  existing weekly updater now follows Devenv's default branch.

### Fixed

- Verify public-cache dependency coverage before publication completes and bind
  repair uploads to the authenticated retained closure. Recover an exact admitted
  official product's cache without repeating GitHub or FlakeHub publication.
- Keep rolling products out of official-release recovery discovery, and select
  fresh observations for the exact admitted official product when reconciling
  its security findings.
- Accept refreshed upstream handoff observations for historical recovery only
  when the complete original product is unchanged. Resolve metadata-only XO
  identities through the pinned caches with hash and availability checks.
- Require separate exact-product approval for rolling and official publication,
  validate canonical identity types strictly, and recheck live human review
  before completing admission.
- Reject obsolete proposal parents before fetching review evidence and refresh
  parent selection when protected main advances during verification.
- Bound optional discovery and evidence recovery, stop discovery after finding
  authenticated matching media, clean up nested processes, and reconcile
  exact-head merge queue state safely across repeated attempts.
- Retry temporary GitHub authority read failures within a bounded budget while
  continuing to deny HTTP 403 responses immediately. Distinguish cache request
  blocks from rejected credentials without exposing headers or response bodies.
- Retain publication verification output, failed destination observations,
  helper failures and original exit status in hosted diagnostics.
- Read native multi-profile scan metadata within a dedicated 128 MiB limit while
  retaining the 16 MiB limit for other packet metadata and all integrity checks.
- Check complete source lines before exempting public SHA-256 ledger keys from
  secret-scanner findings, including keys split across large-document chunks.
  Other credential findings continue to block CI.

## [3.0.1] - 2026-10-20

### Security

- Enable protected publication after the initial appliance security baseline
  and official upstream handoff are verified; retain independent exact-product
  release approval and live admission checks.
- Require current Super Admin approval of complete security findings before
  distributing candidates, and a separate approval of each official release's
  exact product bytes. Preserve findings at every severity and block incomplete,
  stale, or unhealthy scanner evidence.
- Inventory all distributed appliance and operator/tool closures, including
  installed npm dependencies and RustSec findings. Recheck runtime exposure and
  independently verify the pinned XO product's provenance and current admission.
- Include installer runtime, initrd, and bootloader origins in retained security
  evidence, and require review of installer access-policy changes even when no
  vulnerabilities are reported.
- Use the organization Decider App for authority checks and short-lived queue
  credentials, with a separate read-only administration audit App.
- Run pinned CodeQL analysis for Actions, JavaScript/TypeScript, Python, and Rust;
  select the native Nix Rust toolchain for extractor subprocesses.

### Changed

- Export retained Nix closures with Zstandard to reduce CI transport preparation
  time while preserving exact product hashes, authenticated restore, and release
  approval. Already compressed NAR and installer uploads remain uncompressed by
  the artifact service.
- Refresh the XO input to use Nixpkgs' cached Node 22.23.3 and OpenSSL 3.5.9
  runtime without rebuilding the crypto stack.
- Pin the optimized XO runtime, removing native-addon build scaffolding while
  preserving validated Argon2, LevelDB, and FUSE support.
- Separate qualification from publication. Retain authenticated Nix closures and
  immutable release assets so publishers can restore verified products without
  builders and resume interrupted publication without replacing existing bytes.
- Rescan retained products daily while preserving their original product identity
  and approvals. Require review when findings or runtime exposure increase.
- Keep publication frozen during bootstrap until the initial human baselines
  and official XO handoff are configured; see `docs/ci-security.md` for activation.

### Fixed

- Create the publication report directory when validating retained candidates
  downloaded outside the producer's security-report directory.
- Enforce the public CI cache baseline after Determinate configuration while
  preserving explicitly accepted project caches and runtime-only credentials.

- Recover pending decision packets using GitHub's complete PR detail response,
  preserving exact-head and single-file checks when list responses omit counts.
- Diagnose private evidence registry failures with bounded error categories
  while keeping credentials and raw registry responses out of logs.
- Authenticate completed GitHub merge events when queued PR metadata retains
  a stale preview SHA, while preserving content, ancestry and human review.
- Keep immutable decision packet references stable when uploading identical
  evidence again, while preserving producer and scan timestamps.
- Authenticate complete security decision ledgers up to 16 MiB with bounded
  GitHub API output and exact Git object verification.
- Exclude only canonical security finding identity lines from generic secret
  detection; preserve credential detection and review changes to scanner rules.
- Preserve each shipped Nix output in the security inventory and retain plain
  schema and patch inputs by immutable file identity.
- Validate inventory aggregation links while preserving complete appliance and
  installer coverage in the distributed package evidence.
- Match imported XO native package identities to their exact validated Nix
  outputs while retaining the original supply evidence and dependency links.
- Run RustSec audits with the packaged audit binary without requiring Cargo in
  the scanner's environment.
- Verify the complete locked XO closure across the official NixOS, XO, and
  Maestro caches, with signature and content checks and all builders disabled.
- Reuse unchanged installer media by its evaluated ISO and boot-policy identities
  while allowing current supply evidence to refresh independently.
- Reopen weekly dependency update proposals after an earlier reused branch was
  merged or closed, and explicitly enqueue ready trusted updates with exact-head
  checks.
- Keep pinned local Actions compatible with the native workflow linters, retain
  fresh daily vulnerability databases through their publication window, and
  propagate scanner fixture failures.

## [3.0.0] - 2026-10-14

### Breaking changes

- Direct installation now requires `--revision` with a full immutable commit
  SHA. Use the updated `deploy-template` command for the managed Packer path;
  custom installer automation must pass the revision explicitly.
- Installer SSH uses a per-build Ed25519 key enrolled through the VM console.
  Fixed installer passwords are retired; custom Packer workflows must use the
  updated key enrollment and sealing steps.

### Security

- Isolate guest file restore in a bounded, read-only libguestfs RPC helper.
  Guest filesystem parsing and partition/LVM reads stay inside the isolated
  libguestfs appliance;
  the unprivileged host helper streams allowed files into bounded archives.
  Unavailable backends, traversal, links and special files fail closed.
- Run VHD parsing and FUSE mounts as XO. Protect mount roots and reject
  redirected storage paths, with runtime privilege, SSH, TLS and storage checks.
- Use the published XO 6.9.1 runtime with patched OpenSSL 3.5.9 LTS, patched
  appliance libraries and terminal Vim; verify the active crypto implementation.
- Bind native/npm findings to installed packages, immutable sources, derivations,
  patch hashes and appliance context. Preserve raw findings and accept only
  exact, expiring reviewed applicability decisions. npm findings remain visible
  in report mode and are deferred to upstream; no upstream safety claim or new
  deployment acceptance exception is introduced.
- Require protected-main provenance, checksums, matching qualification state and
  signed inventories for artifact reuse and release publication. Keep GitHub PR cache
  operations read-only and resolve credentials at execution time.

### Added

- Retain the native audit manifest, per-target timings and failure phase from the existing audit execution. Record qualification stage durations, exact derivations, build logs and verified-media reuse decisions. Suppress callbacks from unrelated producer branches before controller startup.

- Add audited local validation-cache publication through SecretSpec and `pass`.
  Successful declared outputs can be seeded to the dedicated Maestro Cachix
  cache for subsequent local and hosted runs.
- Add optional CI audit/qualification overlap and event-driven release
  continuation with an immutable, expiring request. Both remain opt-in and
  preserve the complete audit, scan, source, attestation and publication gates.
  The observed overlap pair saved 77 seconds of active time while using 191
  seconds more runner work; it does not establish a general speedup.
- Add runtime XO extra environment-file configuration and optional SecretOps
  password-store references for XCP-ng deployment credentials.

### Changed

- Allow appliance SSH/XO and installer SSH from all IPv4 and IPv6 clients by default
  (`maestro.operator.managementCIDRs = ["0.0.0.0/0" "::/0"]`) for initial deployment.
  Keep SSH key authentication enforced. Add a
  [hardening guide](docs/hardening.md) for restricting management ranges after
  deployment, validating new connections and recovering through the VM console.
- Use the dedicated Maestro cache, retaining XO, devenv and nix-community public
  cache pulls. GitHub publication uses `CACHIX_MAESTRO_AUTH_TOKEN` and the
  `CACHIX_MAESTRO_PUBKEY` variable; public pulls need no write credential.
- Reuse signed supply evidence independently of installer media, batch provenance
  lookups and retain cached CI/SBOM tooling. Size build concurrency to runner CPU
  and memory while preserving the setup-installed Determinate Nix executable.
- Refresh pinned flake/native inputs and fail promptly when prerequisite upstream
  cache publications are unavailable. Serialize release publication in FIFO order
  and preserve release-candidate identity across concurrent main updates.

### Fixed

- Deliver release continuation explicitly after candidate verdict success when
  GitHub suppresses token-created completion events. Bound the completion race,
  handle intentionally skipped audit/preparation ancestors, require successful
  candidate/context/security gates and preserve failed pilot journals.
- Invalidate installer reuse when the embedded appliance closure changes, so
  host management policy and other appliance changes reach newly qualified media.
- Verify final release ISO provenance and its exact SPDX attestation against the
  release source and signer before FlakeHub or GitHub publication. Reject caller
  source drift, changed installer content and mismatched SBOM evidence.
- Restart synchronous release orchestration after a prepared VERSION merge so
  final signing uses the new source identity; preserve the existing CI watch path.
- Preserve complete SBOM metadata with the captured hosted Nix CLI. Materialize
  lazy-tree source metadata when needed, select the actual root Nixpkgs input,
  and restore missing licenses, descriptions and source references while
  preserving package identities and dependencies.
- Decode current Nix derivation JSON and handle immutable patch metadata without
  accepting malformed inventory evidence.
- Keep local installer boot logs writable outside the Nix store and synchronize
  Packer consumers with the current qualification-state schema.
- Preserve guest LVM access, bounded isolated-restore cleanup and service
  readiness checks while retaining file-restore unit coverage.

## [2.0.0] - 2026-08-23

### Changed

- Rebrand the appliance from its former identity to Maestro as a clean 2.0
  boundary. The flake output, NixOS module namespace, operator account, host,
  filesystem state, installer and release artifacts now use `maestro`; the
  supported administration commands are `maestroctl` and `maestro-menu`.
  Compatibility aliases are intentionally not provided.
- Move released 1.x changelog entries into
  `docs/history/legacy-changelog.md`, while retaining the original text as
  historical release documentation.
- Advance qualification-state schema version to 5 and release-manifest schema
  version to 4 so pre-rebrand artifacts cannot be consumed as Maestro output.
- Move live GitHub references to `closure-labs/maestro` and
  `closure-labs/xo-nixpkg`, validate merge-group commits in CI, require GitHub's
  repository merge queue, and preserve every pending publication run with the
  organization-level FIFO concurrency queue. Publish rolling and versioned
  flakes from the matching `closure-labs/maestro` FlakeHub namespace.
- Cache checksummed system and Xen Orchestra supply evidence as a separate
  immutable artifact bound to the exact appliance closure, allowing media-only
  changes to build and boot a new installer without rerunning `sbomnix` while
  preserving the combined installer artifact and release interfaces.
- Build the installer SquashFS with explicit `zstd` level 1 compression,
  reducing compression from about 9m07s to 20s. The accepted installer size
  changed from 2.491 GB to 2.892 GB (about 16%) and remains under an enforced
  3.0 GB artifact budget.
- Keep Maestro CI on public Nix/Cachix substituters and run the required verdict
  directly with runner-provided `jq`, avoiding FlakeHub cache 401s and a second
  Nix/devenv bootstrap after qualification.

### Fixed

- Let failed same-repository Dependabot validation invoke the flake-packaged
  `maestro-ci-fix-hashes` command, remove the write token while Determinate Nix
  evaluates repairs, and push tracked fixes only to the exact PR head.

Released 1.x history is preserved in
[`docs/history/legacy-changelog.md`](docs/history/legacy-changelog.md).
