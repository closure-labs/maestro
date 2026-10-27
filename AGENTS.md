# Repository Guidelines

## Scope

This repository is one appliance flake, not a multi-host framework. Its only
NixOS output is `nixosConfigurations.maestro`, an x86_64 XCP-ng guest running Xen
Orchestra. Do not add host templates, compatibility aliases, or target
selection.

## Structure

- `modules/flake/`: pinned framework composition, input declarations and caches
- `modules/features/`: appliance, platform, operator, XO, installer, XCP-ng and development owners
- `modules/ci/`: graph, checks, inventory, security and live decision authority
- `modules/release/`: publication and consumer contracts
- Ordinary `.nix` files under `modules/` are flake-parts modules. Native NixOS and Home Manager definitions are Den aspect values. Only `_source/`, `_tests/` and `_lib/` contain private files excluded by import-tree.
- `host/settings.nix`: hand-maintained appliance policy
- `host/hardware-configuration.nix`: bootstrap-generated hardware module
- `host/menu.nix`: TUI-generated overrides only
- `docs/features.md`: where to change policy, implementations, tests and CI outputs
- `automation/decisions/`: immutable historical records; never rewrite them during source moves

## Development

Use `.#maestro` in commands and documentation. Edit input declarations in
`modules/flake/inputs.nix`, then regenerate the committed entry point with
`nix run .#write-flake`. Keep input pins unchanged outside deliberate updates.

Full Nix evaluation, audits, builds and VM/ISO tests run in hosted CI. Local
focused fixtures must fit within 512 MiB; never use local full Nix work to bypass
that resource boundary. Graph gating requires recorded hosted comparison acceptance against complete
validation. Preserve all twenty audit obligations and native evidence authority.

```bash
nix flake check --no-write-lock-file
nix build .#nixosConfigurations.maestro.config.system.build.toplevel --no-link
nix build .#xen-orchestra-ce .#maestroctl .#maestro-menu .#installer-iso --no-link
nix run --accept-flake-config .#deploy-template -- --help
nix run --accept-flake-config .#maestro-ci-repository-audit -- --no-write-lock-file
```

`nix run --accept-flake-config .#deploy-template` downloads the latest
successful installer artifact to a temporary directory, verifies its checksum,
and passes it directly to Packer. `INSTALLER_SOURCE=build` is the explicit local
flake-build fallback.

Enter the native toolchain with `devenv shell`; `nix develop
--accept-flake-config` is the compatible flake-only fallback. Run the complete
repository contract with `devenv tasks run ci:repository-audit`. GitHub
workflow command bodies must call declared devenv tasks, which delegate
repository policy to the flake-packaged `maestro-ci-*` leaf commands; do not add
raw CI or release logic to workflow YAML. Do not add a monolithic automation
dispatcher.
Declare credential and repository-variable contracts in `secretspec.toml`.
Resolve values only at runtime; never pass credentials through Nix evaluation
or derivations where they would enter the store.
Run `bash -n` and ShellCheck for shell changes, and run Cargo and Packer checks
through `devenv shell --`; for example, `devenv shell -- cargo test`. When the
native CLI is unavailable, use `nix develop --accept-flake-config --command`.
Do not use a host-installed Cargo or Packer toolchain for repository work.

## Configuration rules

- Declare operator policy under typed `maestro.operator` options.
- Declare XO policy under typed `maestro.xo` options.
- Keep filesystems and disks solely in `host/hardware-configuration.nix`.
- Preserve XO privilege separation and validated storage helpers.
- Preserve the DBus activation safeguards, bounded boot generations, Nix GC,
  Determinate Nix, and XO/libvhdi caches.
- SSH access is only for the declared `maestro` operator.
- The TUI may write only `host/menu.nix`.

## Commits

Use `jj` for local status, history, commits, and bookmarks; GitHub remains the
push and pull-request transport. Commit coherent implementation, tests, and
documentation checkpoints. Keep historical changelog entries intact and
describe public-interface changes in the current changelog section.

## Pull requests

Agent-created and automation PRs must be authored by the configured Decider App,
`cl-decider[bot]`. Use a short-lived installation token scoped to this repository
and verify the returned PR author. Never fall back to Dale's personal GitHub
session when bot authentication is unavailable. Dale is currently the sole
Super Admin and must remain able to approve these PRs independently; GitHub
prevents a PR author from approving their own PR. Preserve actual commit
attribution and keep approval, signing, and publication safeguards unchanged.
