# Documentation

Start by [launching Maestro](installation.md) or
[connecting to an installed appliance](getting-started.md).

## Launch and operate

| Goal | Guide |
|---|---|
| Create a template or build an installer | [Installation](installation.md) |
| Connect and activate a first change | [Getting started](getting-started.md) |
| Apply, update, inspect, and roll back | [Operations](operations.md) |
| Look up an operator command | [`maestroctl` reference](maestroctl.md) |

## Customize and maintain

| Goal | Guide |
|---|---|
| Restrict management access after deployment | [Hardening](hardening.md) |
| Add SSH keys, packages, TLS, or storage | [Common tasks](common-tasks.md) |
| Work with host files and NixOS options | [Configuration](configuration.md) |
| Follow a symptom to focused checks | [Troubleshooting](troubleshooting.md) |

## Build and contribute

| Goal | Guide |
|---|---|
| Enter the toolchain and run checks | [Development](development.md) |
| Review scanner findings and remediation order | [Security review](security-review-2026-10-12.md) |
| Understand appliance composition | [Architecture](architecture.md) |
| Inspect outputs, caches, artifacts, and releases | [Project reference](project-reference.md) |
| Build and seal XCP-ng templates | [Packer reference](../packer/README.md) |

## The three ideas that matter

1. Every appliance command targets the single `.#maestro` output.
2. Durable settings live in `host/settings.nix`; `maestro-menu` records its
   generated overrides in `host/menu.nix`.
3. Preview changes with `maestroctl apply --dry-run`; use `maestroctl rollback --ask` if
   an activated change causes trouble.

Contributors can continue with the
[contribution guide](../legal/CONTRIBUTING.md).
