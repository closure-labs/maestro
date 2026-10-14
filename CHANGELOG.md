<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to published Maestro releases are documented here. This
project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) beginning with
version 1.1.0. Earlier development records are preserved below and may not
correspond to published GitHub tags.

## [Unreleased]

### Changed

- Use the dedicated Maestro Cachix cache for appliance, installer, CLI, native
  devenv and CI builds. Keep XO, devenv and nix-community caches available;
  publish only to Maestro with its repository-specific runtime credential and
  public-key contract. Add SecretSpec references for workstation `pass` entries.
- Keep local installer boot logs in a writable temporary file when the ISO is
  built into the immutable Nix store; preserve explicit hosted log destinations.

- Add local `ci:cache-validation` to audit and publish the exact successful
  validation closures to the configured Cachix cache using runtime credentials.
  Audit manifests live under `.devenv`; hosted execution cannot publish them.

- Download signed evidence without installer media for CI, weekly, and release
  vulnerability scans. `maestro-ci-download-installer DIRECTORY [evidence]`
  keeps full installer verification as its default; publication still verifies
  the ISO and its bound SPDX inventory.
- Batch provenance requests within one invocation, retaining exact source and
  attestation checks while avoiding repeated producer and ancestry API reads.
  `maestro-ci-trusted-run --batch` accepts a JSON request array on stdin.
- Check the active Nix derivation JSON interface before repository validation
  and media builds. Materialize literal coreutils patches in the pinned devenv
  launcher even when its runtime is substituted. Publish the CI toolchain and
  SBOM tooling alongside the existing protected-main cache targets.

- Read versioned Nix derivation JSON for security evidence, including structured
  attributes, input derivations and fixed-output patch paths; retain support for
  older flat responses and reject malformed or unsupported formats explicitly.

- Validate hosted Nix paths and build budgets before exporting runner state
  through the shared setup helper; reject multiline environment injection.

- Remove nested libguestfs file restore acceptance from the CI runtime VM test.
  Keep storage, network, SSH, TLS, service privilege and crypto assertions in
  that test, and retain file restore unit fixtures.

- Size hosted Nix jobs/cores from each runner's CPU and RAM, preserve the
  setup-installed Determinate CLI through packaged audit commands, and make
  env-backed SecretSpec runtime loading explicit in devenv configuration.

- Consume the published XO runtime built against OpenSSL 3.5.9 LTS. Verify the
  active XO process's crypto version and loaded libraries, and wait for bounded
  isolated-restore cleanup in the installed-XO test.

- Restrict appliance SSH/XO and installer SSH ingress to the operator-approved
  `192.168.0.0/16` management range through typed operator policy. Verify allowed
  and rejected client ranges in the booted runtime test.
- Generate source-bound security inventory v2 with complete installed XO npm
  identities, exact Nix derivations, patch hashes and runtime context. Prove
  native/npm scanner coverage and reject incomplete inventories. Replace
  permanent version-only baselines with exact, expiring policy v2 decisions;
  unscored advisories also require review.
- Build Determinate's same pinned source through its public component interface
  against patched appliance libraries. Select patched terminal Vim from the
  XO runtime snapshot, and use specific hostname tools in
  operator wrappers.
- Route guest file restore through an unprivileged, read-only libguestfs RPC
  helper and a source-built appliance with a headless x86 QEMU. Keep partition,
  LVM, file listing and ZIP/TGZ downloads inside the guest kernel. Bound concurrent
  work and runtime; reject traversal, links and special files; fail closed when
  the backend is disabled or unavailable.
- Protect mount directory names with root ownership and sticky permissions,
  claim them through descriptor-based validation, and run VHD parsing/FUSE
  mounting as XO. Add booted storage, TLS, SSH and pathname-boundary tests.
- Declare SecretOps XCP-ng runtime credential variables and optional pass-entry
  resolution. Remove host passwords from installer/Nix preparation subprocesses.
- Request only the installed audit App's Administration read permission for
  policy checks. Allow canceled CI runs to release their runner while keeping
  failure verdicts for active runs.

- Require qualification-state v5 and successful protected-main producer runs
  across CI reuse, releases, and template deployment. Verify the complete signed
  inventory and compare the bound SPDX predicate with the downloaded SBOM.
- Refresh all declared flake and native toolchain inputs, including Determinate
  Nix 3.23.1, the current stable Nixpkgs snapshot, and published XO 6.9.1.
  Check prerequisite caches before building installer media so missing upstream
  publications fail promptly.
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
  Reject storage paths whose configured roots have been redirected by symlinks.
- Add dependency scans, release rescanning, weekly security maintenance, and a
  read-only GitHub policy drift task. Vulnerability gating starts in report mode;
  reviewed baselines and expiring exceptions control later enforcement.
  Use the organization security audit App to mint temporary read-only policy
  tokens, with a policy-only maintenance dispatch for credential checks.

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
