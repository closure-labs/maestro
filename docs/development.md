<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development

The committed devenv module is the development-toolchain and task boundary.
Enter it interactively with:

```bash
devenv shell
```

The flake imports the same package definition, so the compatible Nix interface
provides the toolchain directly:

```bash
nix develop --accept-flake-config
```

For one-off commands, keep the boundary explicit:

```bash
devenv shell -- cargo --version
devenv shell -- packer version
```

The default shell provides the repository's pinned Rust compiler and tooling,
Nix language tools, Packer, GitHub CLI, Secretspec, and workflow and shell
linters.

## Validate a change

Run the complete flake-packaged CI contract before publishing:

```bash
nix run --accept-flake-config .#maestro-ci-repository-audit -- --no-write-lock-file
```

Use the leaf packages directly for individual automation operations:

```bash
EVENT_NAME=workflow_dispatch VALIDATE_ONLY=true \
  nix run --accept-flake-config .#maestro-ci-route
nix run --accept-flake-config .#maestro-ci-classify-paths < changed-paths.txt
nix run --accept-flake-config .#maestro-ci-qualification-inputs
nix eval --json .#lib.ciPlans.x86_64-linux.validation
nix run --accept-flake-config .#run-ci-plan -- \
  --plan lib.ciPlans.x86_64-linux.validation
```

GitHub workflow command bodies invoke declared tasks through the thin pinned
`devenv` flake app. Each task resolves an explicit `maestro-ci-*` leaf package;
there is no umbrella automation dispatcher. Workflow YAML retains only GitHub
runner, permission, environment, artifact, and attestation boundaries. Product
operations use `maestroctl`; delivery automation uses Nix-packaged leaf programs.
Automation programs and security-sensitive XO helpers remain native shell
sources, while Nix provides their runtime dependencies and executable app
boundaries.

Workflow policy allowlists Actions only for GitHub-platform boundaries:
checkout, Determinate Nix bootstrap, artifact upload/download, attestations,
and FlakeHub's OIDC publication. Linters, formatters, compilers, Cachix, and
repository orchestration are ordinary pinned executables supplied by Nix, so
the same commands run locally and on hosted runners.

Hosted leaf tasks use Devenv's `--mode single` so they execute only the named
boundary. The aggregate `ci:repository-audit` task remains dependency-aware
and has no command of its own after its declared flake and formatting checks
finish.

The `maestro-ci-route` command emits one versioned JSON route plan. Focused
qualification, protected-main publication, and the required verdict all
consume that exact output, so downstream jobs cannot independently reinterpret
classification or reuse state. Both the router and verdict validate
`nix/automation/qualification-plan.schema.json`; schema-v3 rejects undeclared
fields, invalid Nix graph digests, and publication without qualification.
The path policy decides whether a change can affect the appliance. When it
can, `lib.ciQualificationInputs.x86_64-linux` supplies separate canonical Nix
graphs for installer media and supply evidence instead of maintaining another
source-path approximation.
Pull requests and pushes fetch full history for path classification;
scheduled and manual validation use the default shallow checkout. Dormant
merge-group support accepts a diff only when both event SHAs exist and the base
is an ancestor of the head, otherwise it requires installer validation.

The `validation`, `media`, `evidence`, and `publish` target sets are versioned
pure values under `lib.ciPlans.x86_64-linux`. Maestro builds them with the validator supplied by its
locked Xen Orchestra input. The schema-v2 runner rejects malformed or duplicate
targets before building, runs each target in a fresh child process against
the shared Nix store, and collects every failure before it exits.

For a focused Rust edit:

```bash
devenv shell -- bash -lc \
  'cd pkgs/maestro-menu && cargo fmt --check && cargo check --locked && cargo test --locked'
```

The flake exposes separate cached checks for automation, qualification-input,
release, operator, and Secretspec contracts, plus ShellCheck, workflow policy
(`actionlint`, `zizmor`, and YAML-aware assertions), and repository invariants.
This keeps failures focused while `ci:repository-audit` runs the complete flake and
formatting contracts. Run focused fixtures through devenv, then finish with
the full task graph.

## Cache behavior

The cache layers have separate responsibilities:

- Cachix stores Nix derivation outputs and shares them between jobs and runs.
- The immutable `maestro-installer` artifact stores the tested ISO, SPDX and
  CycloneDX SBOMs, checksums, attestable state, and artifact pointer.
- The immutable, normally compressed `maestro-evidence` artifact separately
  stores the JSON system SBOMs, XO supply documents, checksums, and
  qualification state. The combined artifact remains uncompressed by GitHub
  because its ISO is already compressed.

Qualification has five deliberately distinct outcomes:

- `skip` means the change cannot affect the appliance.
- `reuse` points at an artifact whose media and evidence identities both match.
- `refresh-evidence` downloads the matching, already-booted ISO and regenerates
  only the system/XO inventories, checksums, and attestations.
- `qualify-media-reuse-evidence` realizes and boots new media, then validates
  and re-attests matching cached evidence without executing `sbomnix`.
- `qualify-media` realizes the ISO, boots it, and then generates its evidence.

The media plan contains only `installer-iso`; the evidence plan contains only
the appliance closure, `sbomnix`, Xen Orchestra, and its supply assertion.
The installer explicitly uses SquashFS `zstd` compression level 1 instead of
nixpkgs' much slower inherited level 19. This intentionally favors fast CI and
qualification over the smallest possible ISO; release assets remain split
below GitHub's per-file size limit. The measured installer moved from 2.491 GB
to 2.892 GB (about 16%); qualification enforces a 3.0 GB ISO budget.
GitHub Actions resets Nix's base substituter to `cache.nixos.org`; the flake's
public Cachix `extra-substituters` are then applied normally. The required
verdict runs the packaged `ci:verdict` task through Nix/devenv, validates the
schema-v3 route contract, and checks required scanning and protected-main
signing results.
Deployment templates, metadata, menus, and CLI packages remain covered by the
repository audit and protected-main publication without being redundantly
realized during installer qualification. Reusable evidence is accepted only
from a successful protected-main run while its artifact is unexpired, its state
matches the exact appliance closure identity, and all retained checksums pass.
Forks may not contribute reusable evidence. The scheduled forced run still
performs a complete media qualification before artifact expiry.

Release workflows serialize their orchestration separately from publication.
The Nix-packaged release manager dispatches qualification with a run-scoped CI
identity, so a later `main` push cannot replace the pending release candidate.
Only jobs that can publish acquire the shared `maestro-publication` queue. Its
`queue: max` policy preserves every pending rolling or versioned publication.

`BOOT_TIMEOUT` remains a failure ceiling, not a normal delay: the QEMU smoke
test exits as soon as the installer reaches its readiness marker. The routine
path already completes in under a minute, so qualification policy and target
selection—not a shorter timeout—are the meaningful performance controls.

Only local pure validation tasks use devenv's `execIfModified`. Hosted tasks
always execute and delegate their implementation to flake-packaged programs;
dependency-free tasks run in isolated single-task mode.

Both `flake.lock` and `devenv.lock` are committed. Refresh them together with
the scheduled updater; `nix run .#maestro-ci-lock-validate` verifies
that their shared nixpkgs and devenv pins match. The root Nixpkgs and Home
Manager inputs use FlakeHub's `/0` stable release trains, and Home Manager
follows the root Nixpkgs input. FlakeHub reserves `/0.1` for rolling unstable
releases, so the repository contract rejects either root input moving there.

## Work with changes

Use Jujutsu for local repository work:

```bash
jj status
jj diff
jj describe -m 'type(scope): summary'
jj bookmark set my-change -r @
jj git push --bookmark my-change
```

Protected `main` requires the stable `Required CI verdict`. Maintenance bots and release
automation use narrowly validated pull requests rather than writing around
that protection. See [Project reference](project-reference.md) for the
immutable installer state, caches, SBOMs, attestations, and release flow.

[Back to documentation](index.md)
