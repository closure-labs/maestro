# Operations

Maestro commands operate directly on the single `.#maestro` appliance.

## Everyday commands

| Goal | Command |
|---|---|
| Check health | `maestroctl status` |
| Review local changes | `maestroctl diff` |
| Preview activation | `maestroctl apply --dry-run` |
| Build without activating | `maestroctl apply --build` |
| Build and activate | `maestroctl apply` |
| Use a new generation after reboot | `maestroctl boot` |
| Roll back | `maestroctl rollback --ask` |
| Follow XO logs | `maestroctl xo logs` |
| Open the console | `maestro-menu` |

For every available command and flag, see the [`maestroctl` reference](maestroctl.md).

## Apply a change

For a normal configuration change:

```bash
maestroctl diff
maestroctl apply --dry-run
maestroctl apply
```

Use `maestroctl boot` to make the new generation active after the next reboot.

## Roll back

```bash
maestroctl rollback --ask
```

The boot menu provides older generations for recovery. Maestro keeps up to ten
boot entries.

## Update

Preview updates before changing the lock file:

```bash
maestroctl update flake --preview
maestroctl update xoa --preview
```

Apply either update with the same command minus `--preview`:

```bash
maestroctl update flake
maestroctl update xoa
```

Review `flake.lock` after a flake update and `.tack/pins.lock.json` after an
XO update. Apply the new generation and record the lock-file update with
`maestroctl commit`.

## Inspect logs

Follow Xen Orchestra and Valkey together:

```bash
maestroctl xo logs
```

Inspect an individual system service with `journalctl`, for example:

```bash
journalctl -u xo-server.service -b
journalctl -u xen-guest-agent.service -b
```

## Save repository changes

```bash
maestroctl diff
maestroctl commit "Describe the appliance change"
maestroctl history
```

## Storage cleanup

Automatic Nix garbage collection runs weekly and removes unreachable paths
older than 30 days. The console also provides manual cleanup.

Manual cleanup can remove generations that would otherwise be available for a
rollback. Check the generation list first:

```bash
maestroctl generations list
```

[Back to documentation](index.md)
