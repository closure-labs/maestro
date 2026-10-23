<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to published Maestro releases are documented here. This
project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) beginning with
version 1.1.0. Earlier development records are preserved below and may not
correspond to published GitHub tags.

## [Unreleased]

- Add optional bounded CI publication summaries and retain execution-bound full diagnostics on success and failure; preserve failed destination observations and original exit status.

- Inspect admitted rolling publication metadata before closure transfers, binding the existing candidate run to its exact current accepted product and producer.

- Retain hosted immutable decision byte reuse observations without caching live authority or uploading proposal contents.

- Let the existing weekly input updater advance Devenv from its default branch while retaining synchronized, reproducible lockfiles.

- Add an opt-in Devenv keyring token prompt and read-only cache permission diagnostic. Keep implicit project credentials out of Nix evaluation; optional default credential declarations move to the explicit `runtime` SecretSpec profile.

- Verify clean-store consumers and publication readback through the existing pinned public cache set, retaining substitution-only execution, exact root hashes, and recursive consumer signature checks.

- Separate scan dependency fingerprints and retain fresh observations while reducing repeated inventory and advisory database work.

- Use a strictly tested signal-only decision relay and minimal native controller task profiles.

- Reconcile publication destinations before transfer and verify remote identities with backward-compatible receipt journals.

- Inspect scheduling and observation metadata before payload transfer, and reuse verified immutable packet bytes within a job while repeating authority checks.

- Bound optional CI transport and required evidence recovery, clean up nested processes, and reconcile exact-head merge queue state idempotently.

- Verify public cache identities before publication completes and exercise public bytes and signatures weekly in a disposable consumer store.

### Changed

- Update the pinned native devenv CLI and modules to 2.4.0, retaining synchronized
  flake and devenv locks without refreshing the appliance package inputs.

- Reduce repeated decision API reads with job-local, hash-verified Git blob reuse,
  while keeping current-main metadata and human authorization checks live.

### Fixed

- Retain native publication verification output and the no-transfer fast path
  in hosted logs using Devenv’s existing task output option.

- Resolve metadata-only XO handoff identities through the existing pinned
  public cache set, retaining fail-closed hash and availability checks.

- Keep admitted rolling products out of official-release recovery discovery,
  while retaining exact-version validation and fresh publication authority.

- Identify cache diagnostics with an explicit HTTP client user-agent and distinguish Cloudflare request blocks from rejected tokens.

- Reject obsolete proposal parents before downloading review evidence, and refresh parent selection when protected main advances during verification.

- Read bounded complete upstream handoff envelopes and permit fresh observations
  for historical recovery only when the entire original upstream product is
  unchanged, retaining independent admission, attestation and freshness gates.

- Reuse verified unchanged installer qualification in the merge queue, refreshing
  evidence separately while retaining fresh builds for changed media and forced
  or scheduled qualification.

- Stop optional discovery once authenticated matching media is found, avoiding
  a timeout-driven rebuild while searching older runs for reusable evidence.

- Require separate exact-product approval for rolling and official publication,
  compare canonical identities with strict schema types, and recheck live review
  before completing admission.

- Select an admitted official product's fresh observations for native security-risk reconciliation before retrying cache recovery.

- Recover an exact admitted official product's cache through the protected publisher without repeating GitHub or FlakeHub publication.

- Detect missing public-cache dependencies before publication completes, bind repair uploads to the authenticated retained closure, and report fixed consumer failure stages.

- Retry bounded temporary GitHub authority read failures and report typed
  rate-limit metadata and fixed failure categories. Preserve immediate denial of
  HTTP 403 responses and keep raw headers, response text and credentials private.

- Read the native multi-profile scans.json observation document with a dedicated 128 MiB bound while retaining 16 MiB limits for other packet metadata and all integrity/deadline checks.

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
