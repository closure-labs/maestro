# Harden management access after deployment

Maestro initially allows SSH (22), HTTP (80) and HTTPS (443) from every IPv4
and IPv6 client through
`maestro.operator.managementCIDRs = ["0.0.0.0/0" "::/0"]`. This makes
the installer and first connection usable from your deployment network.
SSH still requires an enrolled key
for the `maestro` operator; root and password logins remain disabled.

## Restrict management clients

Once deployment is complete, allow only your management network, VPN exit
addresses or individual operator addresses. Use the source address that reaches
the appliance after NAT, including automation clients that still need access.
For example, a management subnet and one VPN client could use:

```nix
maestro.operator.managementCIDRs = [
  "192.168.98.0/24"
  "10.20.30.40/32"
  "fd42:99::/64"
];
```

Replace these examples with your own ranges. Replace the existing assignment
in `host/settings.nix`, inside the `maestro.operator` block, with
`managementCIDRs = [ ... ];`; do not add a second conflicting assignment.
The list must contain at least one valid IPv4 or IPv6 CIDR. `0.0.0.0/0` allows every
IPv4 address; `::/0` allows every IPv6 address. Bare addresses such as
`0.0.0.0` are not CIDRs. Removing all IPv6 ranges closes IPv6 management
ingress; removing all IPv4 ranges closes IPv4 management ingress. Keep manual policy in
`host/settings.nix`, because the console rewrites `host/menu.nix`.

Open the XCP-ng VM console and confirm that you can reach the NixOS boot menu
and identify the current, known-good permissive generation before applying
restrictions. After activation it becomes your previous recovery generation. The default
`maestro` account has no usable console password; an SSH key does not enable
console login. Keep an authenticated SSH session open for immediate rollback
and retain the VM console as the recovery route if that session disconnects.
On the appliance, use:

```bash
maestroctl host edit
maestroctl diff
maestroctl apply --dry-run
maestroctl apply
```

For each configured address family, use an allowed client to establish a **new** SSH connection and open a fresh
HTTPS connection to the XO interface. From a client outside the declared
ranges, verify that new connections to ports 22, 80 and 443 cannot be opened.
Existing connections may survive the firewall change, so an already-open SSH
session does not prove the new policy works. Check any deployment automation
clients as well, then record the policy with `maestroctl commit`.

If new connections fail, run `maestroctl rollback --ask` in the retained SSH
session. If that session is lost, reboot through the XCP-ng console and select
the previous, permissive NixOS generation in the boot menu, then reconnect
using your SSH key. Console execution of `maestroctl` requires console
authentication that you have separately configured. Correct the ranges in
`host/settings.nix` before applying again, and retain recovery generations
until new access has been verified.

The same ranges configure SSH in an installer **built from your checkout**.
Editing the deployed appliance does not alter a downloaded published ISO.
For restricted future installation, set ranges covering the Packer client
before building matching media using `INSTALLER_SOURCE=build`.

## Finish hardening the deployment

- Place the appliance on a management network and apply matching upstream
  network ACLs. Avoid publishing its management ports directly to the internet.
- Review XO accounts, remove or change bootstrap credentials, and grant only
  the permissions operators need. Remove obsolete SSH keys from
  `maestro.operator.sshKeys` and any clone-specific NoCloud key configuration.
- Configure a trusted HTTPS certificate using the [TLS examples](common-tasks.md).
- Keep appliance inputs current using the [update procedure](operations.md),
  back up XO configuration and verify restores before relying on the backup.
- Preserve the existing XO service isolation, storage helpers, closed auxiliary
  listeners and SSH authentication settings when customizing the appliance.

[Back to documentation](index.md)
