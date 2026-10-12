# Project Reference

> This page covers repository and release details for contributors and advanced
> users. Most operators can start with [Getting started](getting-started.md).

## Fixed appliance output

The flake defines one NixOS system:

```text
nixosConfigurations.maestro
```

Its architecture is `x86_64-linux`, its operator is `maestro`, and every
operator command targets `.#maestro`.

## Packages and apps

Public packages include:

- `xen-orchestra-ce`
- `xen-orchestra-supply-protector`
- `libvhdi`
- `maestroctl`
- `maestro-menu`
- `bootstrap`
- `build-template`
- `deploy-template`
- `devenv`
- `installer-iso`
- `metadata`
- `sbomnix`

The flake also exposes operator apps for `maestroctl`, `apply`, `bootstrap`,
`build-template`, `deploy-template`, `commit`, `diff`, `history`, and `menu`.

Run `nix flake show` for the complete evaluated output tree.

Native devenv and the default `devShells.x86_64-linux` output share the
repository toolchain module. Use `devenv shell` for interactive work and
`devenv tasks run ci:repository-audit` for the complete repository contract.
Exact commands and the compatible flake interfaces are in the
[development guide](development.md).

Pure CI target contracts are exported as
`lib.ciPlans.x86_64-linux.validation` and
the focused `lib.ciPlans.x86_64-linux.media` and `.evidence` plans. All use the reusable planner and
Nix-wrapped validator from the locked Xen Orchestra flake; publication,
attestation, and signing remain separate delivery operations.

## Installer delivery

GitHub Actions builds the complete system, public packages, and a
closure-preseeded installer ISO. The ISO is retained as the `maestro-installer`
artifact from the consolidated `CI` workflow. Every Nix-producing CI job reads
from the public Maestro Cachix cache and, on trusted repository events, streams
new outputs back through Cachix's daemon. Cachix carries Nix store paths
between jobs and runs; fork pull requests consume the public cache read-only.
The ISO's SquashFS payload uses explicit `zstd` level 1 compression to minimize
qualification time. The resulting size tradeoff is accepted because the
combined GitHub artifact skips redundant compression and release assets are
already split below the 2 GiB per-part limit.

The Cachix token and cache name are declared in `secretspec.toml`. GitHub
Actions maps the repository secret and variable through Secretspec once per
job, then shares the masked environment with later actions. The flake packages
Secretspec and validates both the public-read and publishing profiles.

Evidence qualification uses the flake-provided `sbomnix` to create validated, checksummed
SPDX and CycloneDX runtime inventories for the complete appliance closure.
Cachix substitutes the system closure, SBOM tooling, and xo-nixpkg's matching
`supply-protector-latest` output. Before attestation, the builder verifies that
the upstream assertion names the exact selected XO store path and Cachix trust
root, verifies its checksums and retained Nix reference, and adds a checksummed
SPDX `DESCRIBED_BY` external-document link to the appliance inventory. The
upstream assertion and its SPDX and CycloneDX documents are preserved with the
installer evidence. The finished SBOMs remain in the combined 90-day
`maestro-installer` artifact and are also retained in a compressed, JSON-only
`maestro-evidence` artifact with their checksums and immutable state. A media-only
change can therefore reuse evidence for the exact appliance closure without
executing `sbomnix`. CI applies the same checksum, SPDX, CycloneDX, XO assertion,
and attestation checks to generated and reused evidence. CI boots a newly
identified ISO with QEMU, signs its build provenance, and binds the SPDX
document to the installer. GitHub release assets carry the tested installer in
numbered parts below GitHub's 2 GiB per-asset limit, plus its whole-file
checksum, both SBOMs, and a checksummed manifest.
Reassemble a directly downloaded installer with `cat maestro-v*.iso.part-* >
maestro-v*.iso`, then verify the matching `.iso.sha256` file. The default
`deploy-template` path performs artifact retrieval and verification itself.

Before allocating the installer runner, the route job classifies the event and
hashes two canonical graphs exported by Nix: the ISO plus its boot policy, and
the system/XO evidence plus its assembly policy. It emits one versioned JSON
plan containing the `skip`, `reuse`, `refresh-evidence`,
`qualify-media-reuse-evidence`, or `qualify-media`
decision and protected-main publication state. Every downstream job and the
required verdict consume that exact plan. An exact unexpired match reuses the
artifact. A media-only match downloads the already-booted ISO and regenerates
its evidence. An evidence-only match realizes and boots new media, then
downloads verified evidence from a successful protected-main run with an
unexpired artifact and matching state. With neither identity available, the
same job generates new evidence after the boot test. Pull
requests, merge groups, and pushes fetch full history for path classification,
while schedules and manual runs keep the shallow checkout. The repository merge
queue runs the same required verdict against the synthetic merge-group commit;
missing, unavailable, or non-ancestral SHAs require qualification. The router
and required verdict share a strict schema-v3 JSON route contract.

At deployment time, `deploy-template` downloads the newest successful `main`
artifact to a temporary directory, verifies state v5, all inventory checksums, protected-main producers, provenance,
and the bound SPDX SBOM, and gives it to Packer. The installer checks out the
pointer's exact `source_commit`; it never follows a moving branch during install.

This means the default installer may briefly lag a newer checkout while CI is
running. Use `INSTALLER_SOURCE=build` for the current checkout or
`INSTALLER_ISO=/path/to/image.iso` for an exact image.

The Determinate, Maestro, and Xen Orchestra binary caches and their public keys
are declared in `flake.nix`; libvhdi is supplied by the Xen Orchestra closure.
Credential-bearing configuration is kept in the runtime Secretspec contract.

## Automation

- Pull requests run flake, source, workflow, lock-health, ShellCheck,
  actionlint, and `zizmor` checks. The stable `Required CI verdict` summarizes the
  conditional graph for branch protection.
- Relevant pull requests select focused qualification from the Nix-owned
  identities. Both media-building routes boot the installer; exact matches
  reuse it, evidence-only changes retain the already-tested media, and
  media-only changes retain validated supply evidence.
- A forced build and boot runs every other month so runtime and cache drift are
  detected before the 90-day artifact expires.
- A scheduled workflow refreshes `devenv.lock` and `flake.lock` every Wednesday
  at 09:17 UTC, verifies their shared pins, and opens or updates one pull
  request.
- Weekly grouped Dependabot updates carry a seven-day cooldown. A narrow bot
  verifies the exact trusted author, repository, branch, title, and head SHA,
  waits for that SHA's CI, and only then enables protected-branch auto-merge.
- Successful installer builds publish the `0.2` rolling FlakeHub release. The
  dedicated release workflow selects a semantic version through a protected
  pull request, verifies the complete signed builder inventory and rescans vulnerabilities, fills a draft GitHub
  release, publishes the versioned flake, and makes the GitHub release
  immutable. Rolling and versioned publication wait in the same non-canceling
  queue so they do not build identical outputs concurrently. The next
  development version passes through the same protection.
- Release, development-version, and flake-input pull requests use the
  repository-scoped `GITHUB_TOKEN`. Trusted automation dispatches CI for the
  exact head SHA, waits for the protected `Required CI verdict`, and enables auto-merge
  after validating the bot identity, branch, title, repository, and allowlisted
  files. Version pull requests carry exactly the `VERSION` change.
- `VERSION` records the current development release. The release workflow
  changes it to the selected stable version and advances it to the next patch
  development version after publication.

See the [Packer reference](../packer/README.md) for the installer build and
template-sealing contract.

[Back to documentation](index.md)

## Security maintenance

PR and merge-group builders have read-only permissions. A separate job signs
only qualified protected-main push, schedule, or dispatch runs. The required
verdict runs the declared `ci:verdict` task and requires dependency scans and
protected-main signing when applicable. Publication failures remain visible
without becoming a merge requirement.

Weekly security maintenance rescans the latest verified inventory and detects
GitHub policy drift. Scanners and vulnerability databases run at execution time,
not in pure Nix derivations. See [Security policy](../SECURITY.md) for baseline
review, enforcement, and expiring exceptions. Configure the optional repository
secret `GITHUB_POLICY_READ_TOKEN` as a repository-scoped fine-grained token with
Administration and Contents **read** access; it is used only by the separate
policy job. No policy drift task changes GitHub settings.

The solo operator owns manual release dispatch and reviews workflow/action
updates. Queue recovery accepts only version, synchronized Nix lockfile, and
Cargo dependency changes. Hash repair remains a maintainer-invoked task.
