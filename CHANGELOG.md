<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to published Maestro releases are documented here. This
project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) beginning with
version 1.1.0. Earlier development records are preserved below and may not
correspond to published GitHub tags.

## [Unreleased]

### Fixed

- Explicitly enqueue ready trusted bot updates, preserving the protected merge
  queue when auto-merge alone leaves an update waiting outside it. Release
  version preparation and advancement wait for successful exact-head CI before
  requesting queue entry; pending ordinary bot updates remain asynchronous.
- Use the scoped `MERGE_QUEUE_PAT` personal token for queue admission so
  GitHub emits native merge-group checks. Keep other automation requests on the
  job token and reject missing queue credentials before requesting auto-merge.

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
