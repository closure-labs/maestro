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

Before allocating product runners, planning resolves the exact appliance,
installer, evidence, and verifier identities. The native router selects `skip`,
`reuse`, `refresh-evidence`, `qualify-media-reuse-evidence`, or `qualify-media`
and binds the route to protected-main producer state. Active graph scheduling
translates that authenticated route into per-job decisions. Every downstream
job and the required verdict consume the bound plan.

An exact unexpired match can reuse authenticated artifacts. A media match
retains the already-booted ISO while regenerating evidence; an evidence match
retains verified supply evidence while qualifying new media. A complete miss
requires fresh qualification. Appliance, installer, inventory, boot, scans, and
verification have explicit job dependencies and exact-output transfer manifests;
new inventory precedes the boot and scan consumers. Retained boot verification
is recorded separately from a newly executed boot test. Missing or incompatible
bindings require complete qualification rather than an optimistic skip.

Pull requests, merge groups, and pushes use immutable candidate/base sources.
The merge queue runs the same required verdict against its synthetic commit;
missing, unavailable, or non-ancestral comparison sources require qualification.
Historical route readers remain available. See [feature navigation](features.md)
for current graph, comparison, and transport contracts.

At deployment time, `deploy-template` downloads the newest successful `main`
artifact to a temporary directory, verifies state v5, all inventory checksums, protected-main producers, provenance,
and the bound SPDX SBOM, and gives it to Packer. The installer checks out the
pointer's exact `source_commit`; it never follows a moving branch during install.

This means the default installer may briefly lag a newer checkout while CI is
running. Use `INSTALLER_SOURCE=build` for the current checkout or
`INSTALLER_ISO=/path/to/image.iso` for an exact image.

The Determinate, Maestro, and Xen Orchestra binary caches and their public keys
are owned by `modules/flake/` and exported through the generated flake.
libvhdi is supplied by the Xen Orchestra closure.
Credential-bearing configuration is kept in the runtime Secretspec contract.
Qualification requires the exact locked XO output to be published in either the
upstream XO cache or the Maestro mirror. Both missing publications fail the
preflight. Mirror availability does not change the upstream supply assertion;
normal Nix realisation still checks the reviewed trusted signatures.

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
  enables protected-branch auto-merge while CI is pending, and explicitly
  enqueues a ready, revalidated exact head through the normal protected queue.
  Ordinary bot updates remain asynchronous.
- Approved installer products publish their exact closures to Cachix. The
  dedicated release workflow selects a semantic version through a protected
  pull request, verifies the complete signed builder inventory and rescans vulnerabilities, fills a draft GitHub
  release and makes the GitHub release
  immutable. Rolling and versioned publication wait in the same non-canceling
  queue so they do not build identical outputs concurrently. The next
  development version passes through the same protection.
- Agent-created and automation pull requests are authored by the configured
  `cl-decider[bot]` App using a short-lived token scoped to this repository.
  Release and development-version preparation retain exact-head CI, independent
  human review, and protected queue admission. Their automated version PRs carry
  exactly the `VERSION` change. Never fall back to the maintainer's personal
  session to create an agent PR; the maintainer must remain able to approve
  independently.
- `VERSION` records the current development release. The release workflow
  changes it to the selected stable version and advances it to the next patch
  development version after publication.

See the [Packer reference](../modules/features/xcp-ng/template/_source/README.md) for the installer build and
template-sealing contract.

Same-repository actions and reusable workflows use GitHub's `$/` references,
which resolve to the running workflow's exact commit independently of checkout
contents. The native workflow check requires this spelling and full SHA pins
for approved external actions. The actionlint syntax check uses an equivalent
workspace-relative copy for compatibility with older pins. Zizmor 1.29 and
later audits the actual source; older versions use the same copy. Reference
pinning and external-action boundaries always validate the actual source.
See [GitHub's self-repository reference documentation](https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax/).

The current release workflow mints a short-lived repository-scoped Decider App
installation token for version preparation and protected queue transport. Its
client ID, private key, and public App ID are declared by the `decision-app`
SecretSpec profile and resolved only at runtime. Native release preparation
receives its queue credential as `MERGE_QUEUE_TOKEN`; the secret never enters
Nix evaluation or derivations. See the [release guide](releases.md) for the
handoff and [CI and security](ci-security.md) for live authority requirements.

[Back to documentation](index.md)

## Security maintenance

PR and merge-group builders have read-only permissions. A separate job signs
only qualified protected-main push, schedule, or dispatch runs. The required
verdict runs the declared `ci:verdict` task and requires dependency scans and
protected-main signing when applicable. Publication failures remain visible
without becoming a merge requirement.

Weekly security maintenance rescans the latest verified inventory and detects
GitHub policy drift. Scanners and vulnerability databases run at execution time,
not in pure Nix derivations. See [Security policy](../SECURITY.md) for source-bound
review, enforcement, and expiring exceptions. The policy job uses organization
variable `SECAUDIT_CLIENTID` and secret `SECAUDIT_PEM` to mint a short-lived
GitHub App token scoped to this repository, with Administration
**read** access. The pinned token action revokes it after the job. These inputs
are declared in Secretspec and stay outside Nix evaluation and derivations.
When REST redacts bypass actors, the reader verifies the exact ruleset's
GraphQL actor count; absent or inaccessible evidence still fails the check.
Dispatch security maintenance with `policy_only=true` to test the credentials
and settings without downloading inventories. No policy drift task changes
GitHub settings.

The solo operator owns manual release dispatch and reviews workflow/action
updates. Queue recovery accepts only version, synchronized Nix lockfile, and
Cargo dependency changes. Hash repair remains a maintainer-invoked task.
