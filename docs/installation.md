# Installation and Launch

Choose the path that matches your starting point:

| Starting point | Use |
|---|---|
| A new appliance from the verified installer | [Launch an XCP-ng template](#launch-an-xcp-ng-template) |
| A new appliance from this checkout | [Build locally](#build-locally) |
| An existing NixOS VM on XCP-ng | [Bootstrap the VM](#bootstrap-an-existing-nixos-vm) |

Creating a template is the recommended path. It gives you a clean appliance
that can be cloned whenever you need it.

## Launch an XCP-ng template

### Before you begin

You need:

- Nix with flakes enabled
- `gh`, authenticated with `gh auth login`
- access to the XCP-ng pool master
- a DHCP-enabled network
- an SSH public key for the `maestro` operator

### Deploy

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

The deployer prompts for XCP-ng details and the password. It stores reusable
non-secret answers in `modules/features/xcp-ng/template/_source/local.pkrvars.json` and accepts the password at
execution time.

> The installer erases the one virtual disk created for the temporary build
> VM. Check the selected storage and VM details before confirming.

### Create your appliance

When the build completes:

1. Clone the `Maestro` template in Xen Orchestra.
2. Attach a NoCloud config drive with an SSH key for `maestro`.
3. Boot the clone and note its IP address.
4. Continue with [Getting started](getting-started.md).

Each clone creates fresh machine and SSH host identities.

## Build locally

Build the current checkout's installer:

```bash
nix build --accept-flake-config .#installer-iso
```

The ISO is available at `result/iso/maestro-installer.iso`. To build that ISO and
send it directly through the template workflow, use the launch command above
with `INSTALLER_SOURCE=build`:

```bash
INSTALLER_SOURCE=build \
  nix run --accept-flake-config .#deploy-template -- ...
```

Set `INSTALLER_ISO=/path/to/maestro-installer.iso` to launch an exact image.

## Bootstrap an existing NixOS VM

This path starts with a bootable `x86_64` NixOS guest on XCP-ng with working
networking and `/etc/nixos/hardware-configuration.nix`.

From the VM:

```bash
git clone https://github.com/closure-labs/maestro.git /tmp/maestro-bootstrap
cd /tmp/maestro-bootstrap

sudo ./modules/features/installer/_source/bootstrap.sh \
  --repo-dir /home/maestro/maestro \
  --ssh-key 'ssh-ed25519 AAAA... operator@example'
```

Replace the example with your complete public key. Repeat `--ssh-key` to add
more than one key.

Bootstrap keeps the VM's generated disk and filesystem configuration, checks
the flake, activates `.#maestro`, and hands SSH access to the `maestro` operator.
Verify the key in a second session before closing the console.

Run `./modules/features/installer/_source/bootstrap.sh --help` for optional settings such as the time
zone, Git identity, branch, or a validation-only install.

## Artifact selection

The default template deployment downloads and verifies the latest successful
installer artifact. The [project reference](project-reference.md) explains its
checksums, SBOMs, attestations, immutable state, and cache reuse. The
[Packer reference](../modules/features/xcp-ng/template/_source/README.md) covers template construction,
validation, and sealing.

[Back to documentation](index.md)
