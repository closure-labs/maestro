# `maestroctl` Reference

`maestroctl` is the command-line interface for the Maestro appliance. Every command
targets `.#maestro`; there is no host selector.

## Commands

```text
maestroctl help
maestroctl version
maestroctl status [--json]
maestroctl apply [--build|--dry-run|--first-install] [--ask] [--cores N] [--verbose] [-- ...]
maestroctl boot [--ask] [--cores N] [--verbose] [-- ...]
maestroctl rollback [--ask]
maestroctl commit [MESSAGE]
maestroctl diff [--json|--staged]
maestroctl history
maestroctl host show [--json]
maestroctl host edit
maestroctl host development-mode [status|on|off|toggle]
maestroctl update flake [--preview] [--ask]
maestroctl update xoa [--preview] [--ask]
maestroctl xo logs
maestroctl generations list
```

## Build and activation

| Command | Result |
|---|---|
| `maestroctl apply --dry-run` | Shows what activation would change |
| `maestroctl apply --build` | Builds without activating |
| `maestroctl apply` | Builds and activates now |
| `maestroctl boot` | Builds and selects the generation for next boot |
| `maestroctl rollback` | Switches to the previous generation |

`--ask`, `--cores N`, and `--verbose` are passed to `nh`. Arguments after `--`
are passed to the underlying build.

`--first-install` is reserved for bootstrap. It uses `nixos-rebuild` directly
before the appliance's declarative Nix configuration is active.

## Repository commands

- `diff` shows changes to Maestro-owned files.
- `commit` stages those files and creates a commit using the configured Git
  identity.
- `history` shows the repository history.

## Host commands

- `host show` reports the fixed target and its policy files.
- `host edit` opens the durable settings and generated menu overrides. Native
  XO overrides are generated from the typed settings during NixOS evaluation.
- `host development-mode` changes the development-tools override.

## Updates

`update flake` refreshes `flake.lock`. `update xoa` uses Tack to refresh the
xo-nixpkg release in `.tack/pins.lock.json`. Add `--preview` to see available
updates without modifying the checkout.

After an update, review the lock-file diff, apply the generation, and record it
with `maestroctl commit`.

## Machine-readable output

- `status --json` returns the status snapshot used by the console.
- `diff --json` returns changed paths and Git status codes.

[Back to documentation](index.md)
