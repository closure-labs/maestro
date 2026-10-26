# Troubleshooting

Start with the appliance summary and Xen Orchestra logs:

```bash
maestroctl status
maestroctl xo logs
```

Then use the section that matches the symptom.

| Symptom | Go to |
|---|---|
| SSH login fails | [SSH access](#ssh-access-fails) |
| Xen Orchestra does not load | [XO service](#xen-orchestra-does-not-start) or [TLS](#tls-fails) |
| A configuration change fails | [Builds and flake output](#a-build-or-flake-command-fails) |
| A menu change vanished | [Generated menu settings](#a-menu-change-disappeared) |
| NFS, CIFS, or VHD fails | [Remote storage](#remote-storage-fails) |
| The VM does not boot | [Hardware and boot](#hardware-or-boot-fails) |
| Template deployment fails | [Template deployment](#template-deployment-fails) |

## SSH access fails

Connect as `maestro` with a public key registered during installation or in the
host configuration.

From the VM console, check the account and effective SSH policy:

```bash
getent passwd maestro
sudo sshd -T | grep -E 'allowusers|passwordauthentication|permitrootlogin'
```

Confirm that your complete public key exists in `host/settings.nix` or
`host/menu.nix`.

For a VM cloned with a NoCloud config drive, also check:

```bash
cloud-id
cloud-init status --wait --long
journalctl -u cloud-init-local.service -u cloud-init.service \
  -u cloud-config.service -b
```

`cloud-id` should report `nocloud`. Without a config drive, Maestro uses the keys
declared in its host configuration.

## Xen Orchestra does not start

```bash
systemctl status redis-xo.service xo-server.service
journalctl -u redis-xo.service -u xo-server.service -b
```

Also confirm that the four generated
`/etc/xo-server/config.nixos-{http,web,redis,remotes}.toml` overrides exist.

## TLS fails

```bash
systemctl status xo-autocert.service
journalctl -u xo-autocert.service -b
sudo openssl x509 -in /etc/ssl/xo/certificate.pem \
  -noout -subject -dates
```

If you supplied your own certificate, confirm that the configured paths exist
and the `xo` service user can read both files.

## A build or flake command fails

Check that the fixed appliance output exists:

```bash
nix flake show
nix eval .#nixosConfigurations.maestro.config.networking.hostName
```

Stage new files before evaluating the flake, or use an explicit `path:` flake
reference so the evaluator includes the working tree.

If `maestroctl apply` reports a dirty checkout, inspect it with:

```bash
maestroctl diff
```

Maestro reports a dirty checkout so you can review the exact changes before
activation.

## A menu change disappeared

`maestro-menu` rewrites `host/menu.nix` as a complete generated override. Move
durable manual changes to `host/settings.nix`.

## Remote storage fails

Follow the logs while reproducing the problem:

```bash
maestroctl xo logs
```

Mount targets must be below the configured `maestro.xo.storage.mountsDir`. VHD
paths must be below the XO mounts, data, or temporary directories. Confirm that
the required protocol is enabled in `maestro.xo.storage`.

The privileged helper validates operations, enabled filesystems, safe path
roots, and credential-file usage.

## Hardware or boot fails

Compare `host/hardware-configuration.nix` with the VM's generated hardware
configuration. Check that its filesystem declarations and firmware-specific
bootloader settings still match the VM.

Select a known-good generation from the systemd-boot menu to recover the
appliance.

## Template deployment fails

Always run the flake-provided deployer; it includes the pinned Packer plugin:

```bash
nix run --accept-flake-config .#deploy-template -- --help
```

Authenticate GitHub CLI for installer artifact access:

```bash
gh auth login
```

You can bypass the artifact and build the current checkout locally:

```bash
INSTALLER_SOURCE=build \
  nix run --accept-flake-config .#deploy-template -- ...
```

For detailed Packer behavior and clone validation, see the
[Packer reference](../modules/features/xcp-ng/template/_source/README.md).

## Xen warnings

A Valkey warning about the Xen clocksource is usually informational. Maestro
keeps Xen's selected clocksource because it remains safe across VM migration,
save, and restore.

The Xen guest agent may also report extra IPv6 netlink data from a newer
kernel. If the service stays active and XCP-ng receives the guest addresses,
the message is informational.

[Back to documentation](index.md)
