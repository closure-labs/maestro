# Security policy

Report suspected vulnerabilities through this repository's **Security → Report
a vulnerability** page. Do not include credentials or exploitation details in
public issues. Reports cover the latest published Maestro release and current
protected `main`; reproduce against current dependencies when practical.

Maestro is one administrative appliance. The declared `maestro` operator is
root-equivalent through sudo and trusted Nix access. XO uses a separate service
account and narrowly validated storage commands. Restrict management interfaces
and the VM console to trusted administrators. Replace initial XO administrator
credentials before exposing the appliance beyond the build network. Automatic
TLS certificates are self-signed; distribute their fingerprint or configure a
trusted certificate through typed `maestro.xo` options.

The operator's approved management range is `192.168.0.0/16`, declared through
`maestro.operator.managementCIDRs`. SSH and XO HTTP/HTTPS accept new connections
only from that IPv4 range; IPv6 management ingress stays closed. Installer SSH
uses the same range and per-build key enrollment through the VM console.

Guest file restore uses a read-only libguestfs appliance as XO. Guest filesystem
and LVM parsing stays in that disposable kernel; files are downloaded through
RPC into private pipes, with no host mounts or guest-named host output files.
The helper rejects traversal, selected symlinks and special files, admits one
request at a time, and enforces a 15-minute deadline. A disabled or unavailable
backend fails closed.

Only successful protected-main CI artifacts may enter release or GitHub-backed
template deployment. Consumers check state v5, checksums, immutable source
commits, producer identity, provenance, and the bound SBOM. Select local/build
media explicitly when working on unpublished changes.

Vulnerability scans remain in report mode until complete Nix/npm inventories,
runtime remediation, and appliance acceptance pass. Policy schema v2 in
`nix/automation/security-policy.json` contains `dispositions` and `exceptions`;
permanent version-only baselines are rejected. Each record identifies the
advisory, component, version, severity, and exact `identity` from the fresh
finding, plus an owner, reason, HTTPS evidence, and `created`/`expires` dates.
Dispositions also declare `kind` as `fixed` or `not_affected`. All records expire
within 30 days. Derivation, patches, system configuration, installed manifests,
scanner, or advisory applicability changes invalidate the identity and require
renewed review.

Enforcement blocks unresolved high, critical, and unscored findings. Scanner
coverage probes must detect known vulnerable Nix and npm components; missing
inventory, scanner/database failures, malformed decisions, and expired records
fail in both modes. Raw scanner reports retain their original severity and
matches alongside reviewed decisions. No general package-wide exemption is
permitted.

Workflow/action updates require operator review. Automatic queueing is limited
to narrowly validated version, Nix lockfile, and Cargo dependency changes. Use
`automation:fix-hashes` locally after reviewing a failed dependency update;
privileged repair never runs from PR CI.

Use `ci:security:policy-drift` to compare GitHub settings with the checked-in
policy. It only reads settings and fails on drift or unavailable evidence.
