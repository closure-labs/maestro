<!-- SPDX-License-Identifier: Apache-2.0 -->
# Packer deployment

The repository can build and deploy Maestro without installing Packer into a
profile or into the appliance:

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
  --memory-mb 4096 \
  --disk-size-mb 20480 \
  --operator-key ~/.ssh/id_ed25519.pub
```

Nix supplies Packer from pinned nixpkgs and builds the Vates XenServer plugin
at pinned version 0.11.4. Both live only in the caller's Nix store. Neither is
added to `nixosConfigurations.maestro`.

The helper saves non-secret pool settings to the ignored
`packer/local.pkrvars.json`. It never writes the XCP-ng password. Set
`XCP_HOSTPASSWORD` through the SecretOps runtime profile, or set
`XCP_PASSWORD_PASS_ENTRY` to a password-store entry that the deployer resolves
after configuration. `PKR_VAR_remote_password` remains supported; otherwise
the helper prompts without echo. These values are declared in
`secretspec.toml`. The builder removes password variables before preparing
the installer or running Packer initialization and injects the password only
into the Packer build process. Never put passwords in variable files or Nix
configuration.

The lower-level builder is also a first-class app. It consumes an existing
Packer variable file without running the interactive configuration step:

```bash
nix run --accept-flake-config .#build-template -- \
  -var-file=packer/local.pkrvars.json
```

Both apps use the same Nix-packaged Packer and XenServer plugin. Run them from
the checkout whose `packer/` sources and appliance flake should be built, or
set `MAESTRO_SYSTEM_ROOT` explicitly.

GitHub Actions builds the deployer, appliance packages, complete system, and
installer ISO. The complete, closure-preseeded ISO is retained for 90 days as
the `maestro-installer` workflow artifact; only the smaller reusable Maestro
packages are pushed to Cachix. `nix run --accept-flake-config
.#deploy-template` downloads the artifact from the newest successful `main`
workflow run into a temporary directory, verifies its SHA-256 checksum, and
passes it directly to Packer. Run `gh auth login` once before using the
deployer.

The Maestro, XO, devenv, nix-community and Determinate substituters and public
signing keys are declared directly in `flake.nix`.
The GitHub artifact is deliberately resolved by the flake app's runtime helper,
not declared as a flake input or pinned in `flake.lock`. It may briefly lag the
checkout while a newer `main` workflow is still running. Set
`INSTALLER_SOURCE=build` for an exact build of the current checkout, or
`INSTALLER_ISO=/path/to/image.iso` to deploy a specific image.

## What the build does

1. The deployer downloads the headless, UEFI-only installer built from
   `packages.x86_64-linux.installer-iso` by GitHub Actions and gives its
   checksum-verified path directly to Packer. Set `INSTALLER_SOURCE=build` to
   build it locally or `INSTALLER_ISO=/path/to/image.iso` to use an existing
   image. The ISO remains limited to the
   Xen unattended-install path and uses networkd for DHCP, but its Nix store is
   preseeded with the complete generic Maestro system closure, `maestro-menu`, and
   Xen Orchestra so first installation needs only source metadata and small
   machine-specific derivations from the network.
2. Packer uploads that ISO to the selected ISO SR and creates one UEFI VM with
   one disk and a DHCP network.
3. The live installer requires explicit destructive confirmation, partitions
   only that single Packer disk, clones `maestro`, writes the operator key, and
   generates the hardware module.
4. `nixos-install` installs `.#maestro`; the VM reboots twice while Packer verifies
   cloud-init, Xen guest integration, Redis, XO, TLS, and SSH. Packer gives XO a
   fixed four-minute startup grace period only on the installed system's first
   boot; the second verification retries its endpoint immediately.
5. The final provisioner restores key-only SSH, commits generated host policy,
   removes obsolete Nix generations and store paths with `nh clean all`, clears
   cloud-init and machine identity, removes SSH host keys, and lets the
   XenServer plugin mark the VM as a native template.

The installer is the only component that creates or formats partitions. The
installed appliance continues to use `host/hardware-configuration.nix` as its
sole disk and filesystem declaration source; on a clone, cloud-init may extend
only the existing root partition and filesystem to consume a larger virtual
disk.

## Clone validation

Create a VM from the template, attach a Xen Orchestra NoCloud config drive with
an SSH key for `maestro`, and boot it. Then run:

```bash
sudo /home/maestro/maestro/packer/scripts/verify-clone.sh
```

The check requires a NoCloud datasource, new machine and SSH identities,
key-only SSH, healthy Redis/XO services, and a responding HTTPS endpoint.

The installer and template use key-only SSH throughout. Each build creates a
private Ed25519 key in a protected temporary directory on the builder. Packer
enrolls its public key through the VM console; the private key never enters the
guest or the Nix store. The temporary public key survives the first reboot and
is removed by sealing. The operator key remains authorized. The VM console is
a trusted administrative channel; an installer without enrollment has no remote
SSH access.

GitHub-backed builds require signed qualification state v5 and the complete
verified installer inventory from successful protected-main CI. Unsigned or
older state requires fresh qualification; there is no silent local fallback.
Packer installs the selected state's exact commit. Local/build media remain
explicit choices and resolve `REPO_BRANCH` once, or accept `REPO_REVISION`.
Direct `install-maestro` calls require `--revision SHA`; Packer supplies this
and the optional `--bootstrap-key FILE` automatically.
