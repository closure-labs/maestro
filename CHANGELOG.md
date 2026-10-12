<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to published Maestro releases are documented here. This
project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) beginning with
version 1.1.0. Earlier development records are preserved below and may not
correspond to published GitHub tags.

## [Unreleased]

### Changed

- Require qualification-state v5 and successful protected-main producer runs
  across CI reuse, releases, and template deployment. Verify the complete signed
  inventory and compare the bound SPDX predicate with the downloaded SBOM.
- Separate read-only qualification from protected-main signing and publication;
  run the required verdict through its declared devenv task. Retire privileged
  PR hash repair and restrict automatic update queueing to dependency/version
  paths, leaving workflow/action updates to operator review.
- Replace fixed installer passwords with per-build Ed25519 public-key enrollment
  through the VM console. Pin installed source to an immutable commit; direct
  installation now requires `--revision`, with optional `--bootstrap-key`.
- Add runtime `maestro.xo.extraServerEnvFiles`, stricter storage-helper parsing,
  and SSH, service identity, Valkey, capability, and sudo assertions.
  Keep temporary CIFS credentials beneath a root-owned runtime directory.
- Add dependency scans, release rescanning, weekly security maintenance, and a
  read-only GitHub policy drift task. Vulnerability gating starts in report mode;
  reviewed baselines and expiring exceptions control later enforcement.

### Fixed

- Synchronize the Packer consumer and fixtures with qualification-state v5.

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
