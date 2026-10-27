# Maestro

**Run Xen Orchestra on XCP-ng with reproducible builds and reversible upgrades.**

Maestro packages Xen Orchestra Community Edition as one NixOS appliance.
Build a sealed template, clone it for your pool, and manage the appliance through
a guided console or `maestroctl`. Each clone starts with its own machine and
SSH host identities.

```text
XCP-ng pool  →  Maestro virtual machine  →  Xen Orchestra web interface
```

## What you get

- **Repeatable deployment:** a verified installer and a sealed XCP-ng template.
- **Reviewable configuration:** typed operator and XO settings for one `.#maestro` appliance.
- **Reversible changes:** preview activation, keep boot generations, and roll back.
- **Traceable delivery:** SPDX and CycloneDX inventories, checksums, and build attestations.
- **Daily operation:** inspect health, configure the appliance, and follow XO logs
  from the console or CLI.

## Launch Maestro

Install Nix and Git, authenticate GitHub CLI with `gh auth login`, and have an
SSH public key plus XCP-ng pool access ready. Then run:

```bash
git clone https://github.com/closure-labs/maestro.git
cd maestro

nix run --accept-flake-config .#deploy-template -- \
  --host XCP_POOL_MASTER \
  --iso-sr "ISO library" \
  --sr "Local storage" \
  --network "VM network" \
  --export-network "VM network" \
  --template-name Maestro \
  --operator-key ~/.ssh/id_ed25519.pub
```

The deployer downloads the latest verified installer, prompts for XCP-ng
details, and builds a sealed `Maestro` template. It saves reusable non-secret
answers while accepting the XCP-ng password at execution time.

Clone the template, attach a NoCloud config drive with the operator SSH key,
and boot the appliance. Continue with the
[first-login guide](docs/getting-started.md), then
[restrict management access](docs/hardening.md) for your network.

## Build from this checkout

Build the installer ISO directly from the flake:

```bash
nix build --accept-flake-config .#installer-iso
```

The ISO is available at `result/iso/maestro-installer.iso`. Build and deploy the
same checkout in one operation with:

```bash
INSTALLER_SOURCE=build \
  nix run --accept-flake-config .#deploy-template -- \
  --host XCP_POOL_MASTER \
  --iso-sr "ISO library" \
  --sr "Local storage" \
  --network "VM network" \
  --export-network "VM network" \
  --template-name Maestro \
  --operator-key ~/.ssh/id_ed25519.pub
```

The [installation guide](docs/installation.md) also covers bootstrapping an
existing NixOS guest and supplying an exact installer image.

## First login

Open Xen Orchestra at `https://<vm-address>/`, or connect to the appliance:

```bash
ssh maestro@<vm-address>
maestroctl status
maestro-menu
```

Use `maestroctl apply --dry-run` to preview a configuration generation and
`maestroctl apply` to activate it.

## Release highlights

The next release, **3.2.0**, brings feature-owned configuration and an active CI
graph that binds each job to the exact products and evidence it verifies.
Complete validation, fresh security scans, and human publication approvals remain
required. Delivery targets are Cachix and GitHub releases; Maestro no longer
publishes new versions to FlakeHub.

See the [changelog](CHANGELOG.md) for the release notes and the
[release guide](docs/releases.md) for preparation, staging, and approval.

## Documentation

| Goal | Guide |
|---|---|
| Install and connect | [Installation](docs/installation.md) and [getting started](docs/getting-started.md) |
| Operate and update | [Operations](docs/operations.md) and [`maestroctl` reference](docs/maestroctl.md) |
| Customize the appliance | [Common tasks](docs/common-tasks.md) and [configuration](docs/configuration.md) |
| Diagnose an issue | [Troubleshooting](docs/troubleshooting.md) |
| Build and contribute | [Development](docs/development.md), [architecture](docs/architecture.md), and [project reference](docs/project-reference.md) |

The complete task-oriented map is in the [documentation index](docs/index.md).

Maestro is licensed under the [Apache License 2.0](LICENSE). Contributions are
welcome; see the [contribution guide](legal/CONTRIBUTING.md).
