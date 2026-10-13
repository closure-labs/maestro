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

Only successful protected-main CI artifacts may enter release or GitHub-backed
template deployment. Consumers check state v5, checksums, immutable source
commits, producer identity, provenance, and the bound SBOM. Select local/build
media explicitly when working on unpublished changes.

Vulnerability scans start in report mode. The operator reviews findings and
records accepted high/critical findings in `nix/automation/security-policy.json`
before changing `mode` to `enforce`. Baseline entries identify advisory,
component, version, severity, owner, and reason. New high/critical findings then
block required scans. Missing severity requires manual triage and is not a
claim of safety. Expiring exceptions include advisory, component, version,
owner, reason, `created`, and `expires` (UTC dates), with a maximum of 30 days.
Database and scanner errors fail the scan in both modes.

Workflow/action updates require operator review. Automatic queueing is limited
to narrowly validated version, Nix lockfile, and Cargo dependency changes. Use
`automation:fix-hashes` locally after reviewing a failed dependency update;
privileged repair never runs from PR CI.

Use `ci:security:policy-drift` to compare GitHub settings with the checked-in
policy. It only reads settings and fails on drift or unavailable evidence.
