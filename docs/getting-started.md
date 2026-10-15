# Getting Started

This guide begins after Maestro is installed. If you still need to create the
appliance, start with [Installation](installation.md).

## 1. Connect

Find the VM address in XCP-ng or Xen Orchestra, then connect with the SSH key
used during installation:

```bash
ssh maestro@<vm-address>
```

The appliance uses SSH-key authentication for the `maestro` operator.

## 2. Open Xen Orchestra

Visit:

```text
https://<vm-address>/
```

Maestro creates a self-signed certificate by default, so your browser will show a
warning on the first visit. You can replace the certificate later.

## 3. Check the appliance

```bash
maestroctl status
maestroctl xo logs
```

For a guided interface, run:

```bash
maestro-menu
```

## 4. Make a safe change

Use `maestro-menu`, or edit the durable configuration:

```bash
maestroctl host edit
```

Then review and preview the change before activating it:

```bash
maestroctl diff
maestroctl apply --dry-run
maestroctl apply
```

If the new generation causes a problem:

```bash
maestroctl rollback --ask
```

## Next steps

- [Hardening](hardening.md) to restrict the initial all-IPv4/IPv6 management access
- [Common tasks](common-tasks.md) for SSH keys, packages, TLS, and storage
- [Operations](operations.md) for updates, boot generations, and logs
- [Troubleshooting](troubleshooting.md) for symptom-based checks and recovery

[Back to documentation](index.md)
