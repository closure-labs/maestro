# Configuration

Most appliance policy changes begin in one file:

```text
host/settings.nix
```

It contains durable appliance settings such as the time zone, SSH keys,
packages, TLS, and storage support. Run `maestroctl host edit` to open the host
configuration files.

## Configuration files

| File | Purpose | Maintained by |
|---|---|---|
| `host/settings.nix` | Durable appliance policy | Operator |
| `host/hardware-configuration.nix` | Generated disks, filesystems, and detected hardware | Hardware workflow |
| `host/menu.nix` | Console-generated overrides | `maestro-menu` |

The menu rewrites `host/menu.nix` as a complete file. Put lasting manual
changes in `host/settings.nix`.

## Safe editing workflow

```bash
maestroctl host edit
maestroctl diff
maestroctl apply --dry-run
maestroctl apply
```

Maestro creates a new NixOS generation for every applied change. If needed, use
`maestroctl rollback --ask`.

## Common settings

The main Maestro options are grouped by purpose:

| Option group | Controls |
|---|---|
| `maestro.operator.sshKeys` | SSH public keys for the `maestro` account |
| `maestro.operator.systemPackages` | Packages available system-wide |
| `maestro.operator.userPackages` | Packages for the operator |
| `maestro.operator.enableExtras` | Extra shell tools and zsh |
| `maestro.operator.developmentMode` | Rust, Node.js, and development tools |
| `maestro.operator.menuAutoStart` | Whether the console opens at SSH login |
| `maestro.xo.channel` | `latest`, `stable`, or `rolling` xo-nixpkg output; defaults to `latest` |
| `maestro.xo.tls` | HTTPS certificates |
| `maestro.xo.storage` | NFS, CIFS, and VHD support |
| `maestro.xo.tempDir` | Node.js temporary directory supplied through `TMPDIR` |

Maestro supplies the operator name, `.#maestro` flake target, platform, and
appliance role as stable appliance defaults.

The appliance selects xo-nixpkg's `latest` official-release output by default.
Set `maestro.xo.channel = "stable"` to retain the preceding official release, or
use `"rolling"` temporarily when troubleshooting against an admitted upstream
commit. An explicit `maestro.xo.package` still overrides the channel-derived
package.

Xen Orchestra first loads its immutable vendor `config.toml` from the
`xo-nixpkg` package. The NixOS module maps one declarative attribute set into
four focused system overrides under `/etc/xo-server/`:

- `config.nixos-http.toml` owns listeners, TLS, and HTTPS redirection.
- `config.nixos-web.toml` owns the packaged web-interface mounts.
- `config.nixos-redis.toml` owns the managed Redis-compatible socket.
- `config.nixos-remotes.toml` owns remote mount policy.

These generated files do not overlap and are not edited directly. Change their
typed `maestro.xo` inputs in `host/settings.nix`. Node.js receives the managed
temporary directory through `TMPDIR`; it is not represented as an unsupported
XO TOML key.

See [Common tasks](common-tasks.md) for copyable examples.

## Native NixOS settings

`host/settings.nix` can also set normal NixOS options. The checked-in defaults
include the host name, time zone, bootloader, firewall ports, and state version.

Keep `system.stateVersion` at the compatibility version used when the
appliance was first installed.

## Hardware changes

`host/hardware-configuration.nix` is the only source of filesystem, swap, and
disk declarations. If the VM hardware changes, generate a candidate on the
appliance and review it before replacing the existing file:

```bash
sudo nixos-generate-config --show-hardware-config \
  > /tmp/hardware-configuration.nix
```

NoCloud can install clone-specific SSH keys, adopt a DHCP hostname, and grow
the existing root partition and filesystem when a cloned disk is larger.

[Back to documentation](index.md)

## Runtime XO secrets

`maestro.xo.extraServerEnv` is for non-secret values because Nix renders them
into the system closure. Use `maestro.xo.extraServerEnvFiles =
[ "/run/secrets/xo.env" ];` for runtime systemd environment files. The option
accepts absolute filename strings outside `/nix/store`; provision file contents
separately, restrict their permissions, and never use a Nix path literal or
`builtins.readFile` for a secret. Missing configured files prevent XO startup.
