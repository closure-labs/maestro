# Architecture

> This is an advanced reference for contributors. For normal installation and
> operation, start with [Getting started](getting-started.md).

Maestro is intentionally a single-appliance Den flake. `flake.nix` evaluates the
`modules/` import tree, and Den materializes one host entity:

```text
den.hosts.x86_64-linux.maestro
└── nixosConfigurations.maestro
```

The `maestro` host aspect composes four focused aspects:

```text
maestro
├── platform   NixOS base, networking, Nix policy, DBus safeguards
├── xcp-ng     Xen guest agent and constrained NoCloud provisioning
├── xo         Xen Orchestra service, TLS, and storage
└── operator   maestro account, SSH, Home Manager, maestroctl, and menu
```

The flake exports one concrete appliance configuration and one operator-side
template builder.

XO's home and mount ancestors are root-owned and sticky, with group write
access for the XO account. A focused descriptor-based guard claims directory
names before root mounts, so XO cannot rename a validated ancestor. Final
mountpoints are root-owned and group-writable without a sticky bit, as required
by unprivileged FUSE. VHD parsing and mounting run as XO, with FUSE access
restricted to XO and root for validated unmounts; NFS/CIFS use the
validated root helper. Explicit tmpfiles rules own this layout, avoiding
systemd state-directory ownership changes on service restart.

The native XCP-ng template builder runs on the operator workstation.
`packages.x86_64-linux.installer-iso` evaluates a small live installer, while
`nix run --accept-flake-config .#deploy-template` realizes Packer and its
XenServer plugin in the caller's Nix store. The installed system is
`nixosConfigurations.maestro`.

The flake directly declares the Determinate, Maestro, and Xen Orchestra binary
caches. Integrated libvhdi comes from the Xen Orchestra flake. The
multi-gigabyte installer is instead a GitHub Actions
artifact: the `deploy-template` app selects the newest successful `main` run,
downloads and verifies the ISO at deployment time, and passes its temporary
path to Packer. The source flake and runtime installer selection stay
independently pinned. An exact checkout-local ISO is available through
`INSTALLER_SOURCE=build`.

Repository delivery is Nix-defined and flake-packaged. Hosted workflow command
bodies call declared devenv tasks through a thin flake app, and those tasks
execute explicit `maestro-ci-*` leaf packages. No umbrella automation app or
dispatcher sits between the task graph and those Nix derivations. Workflows
retain GitHub security
boundaries—permissions, OIDC, artifacts, attestations, Cachix, and GitHub releases.
The organization audit App requests repository-scoped Administration read
access; the policy endpoints do not require Contents permission.
The work router combines source classification and immutable artifact reuse
into one versioned JSON plan consumed by later jobs and the required verdict.
A Nix policy declares which source paths affect the immutable installer
fingerprint, allowing metadata-only commits to reuse a previously verified
artifact while unknown paths fail safely toward rebuilding. The same policy
filters both changed paths and the tracked-file fingerprint, preventing
classification and reuse from disagreeing. Only
path-classifying events fetch full Git history, and future merge-group
classification also fails toward rebuilding unless its base is a known
ancestor of its head. Hosted leaf tasks run in isolated Devenv mode. Release
workflows serialize independently, release-owned qualification runs use a
run-scoped CI identity, and only rolling and versioned publication jobs share
the non-canceling publication queue. The router and required verdict validate
the same strict JSON Schema, so field, type, digest, and lifecycle invariants
cannot drift between them.

## Module layout

```text
modules/
├── dendritic.nix
├── den-defaults.nix
├── host.nix
├── aspects/
│   ├── platform.nix
│   ├── xcp-ng.nix
│   ├── xo.nix
│   └── operator.nix
├── _nixos/
│   ├── platform.nix
│   ├── xcp-ng.nix
│   ├── operator.nix
│   └── xo/
│       ├── default.nix
│       ├── service.nix
│       ├── tls.nix
│       └── storage.nix
└── _homeManager/
```

The underscore directories contain class modules composed through the aspect
tree.

## Host ownership

`host/default.nix` imports three policy layers:

- `settings.nix`: operator-maintained settings
- `hardware-configuration.nix`: generated during bootstrap and the sole source
  of filesystems, swap, disks, and hardware discovery
- `menu.nix`: generated console overrides

Menu-managed operator values are defaults in `settings.nix`, so explicit values
in `menu.nix` take precedence without allowing the TUI to rewrite durable
policy.

## Clone provisioning

The XCP-ng aspect enables cloud-init for Xen Orchestra NoCloud config drives.
Its scope is deliberately narrow: select `NoCloud` with a `None` fallback,
target the existing `maestro` operator, install datasource SSH keys, and create
per-instance SSH identity. Declarative NixOS configuration remains authoritative
for accounts, sudo, network configuration, filesystem declarations, packages,
and services. Cloud-init installs NoCloud SSH keys and can grow the existing
root partition and filesystem. systemd-networkd applies a DHCP-provided
transient hostname through the narrowly authorized hostnamed action.

SSH starts after `cloud-config.service`, ensuring NoCloud keys are processed
before the operator connects.

## XO runtime

`modules/_nixos/xo/service.nix` owns the `xo` account, Valkey instance,
generated TOML, filesystem layout, and hardened `xo-server` unit.

`tls.nix` creates a long-lived self-signed certificate when configured files
are absent or expired.

`storage.nix` provides NFS/CIFS/VHD support. XO remains unprivileged; mount and
libvhdi operations cross privilege boundaries through a validated root helper
and a narrow sudo rule. CIFS credentials travel over standard input and use a
short-lived, root-readable credential file.

## Operational invariants

- target and host entity: `maestro`
- architecture: `x86_64-linux`
- hypervisor: XCP-ng/Xen
- operator: `maestro`
- initial state version: `26.05`
- direct XO package:
  `inputs.xen-orchestra-ce.packages.x86_64-linux.latest`

Guest file restore uses `maestro.xo.fileRestore.enable` (enabled by default).
XO sends partition/list/archive requests to a trusted absolute helper. The
helper runs as XO, opens the raw FUSE disk read-only with an explicit raw format,
and uses libguestfs RPC inside a source-built appliance. No guest filesystem or
LVM metadata reaches the host kernel. QEMU is headless, networking is disabled,
and each request gets one CPU and 512 MiB; a lock admits one request at a time
and a 15-minute deadline bounds it. Files stream through private pipes into
ZIP/TGZ archives; guest paths never name host output files. Traversal, selected
symlinks and special files are rejected. Client disconnect terminates the
helper before releasing its raw VHD view. Disabling the feature makes restore
fail closed instead of restoring the legacy host mount path.
The manual host partition-mount API is disabled while isolated restore is configured.

Management access uses typed `maestro.operator.managementCIDRs`, with the
initial-deployment `0.0.0.0/0` and `::/0` ranges in `host/settings.nix`. Appliance SSH
and XO HTTP/HTTPS, plus installer SSH, accept all IPv4 and IPv6 clients by default. Restrict the ranges after deployment
using the [hardening guide](hardening.md). Management ports
are absent from global allow lists, and each address family is restricted to its declared CIDRs.
The VM console and per-build key enrollment provide the installation recovery
path; new deployments qualify that path in the disposable lab.

[Back to documentation](index.md)
