# Incoming secret scanning and historical debt

Maestro adapts the conventional official Gitleaks CLI implementation from
xo-nixpkg PR #206, exact head
`494fe1170e896f9bd9a57554e34ad61f507a99e2`:
https://github.com/closure-labs/xo-nixpkg/pull/206
The upstream CLI and Git range semantics are documented at
https://github.com/gitleaks/gitleaks/tree/v8.30.1 and
https://git-scm.com/docs/git-log .

`ci.yml` calls the read-only reusable `repository-secret-scan.yml` on every
`pull_request` and `merge_group`, independently of route classification,
qualification, retained evidence and decision-only reuse. `Required CI verdict`
waits for that call and requires success for both incoming event types. Missing,
skipped, cancelled and failed scans block the existing required verdict; no
repository settings change or synthetic check publisher is needed.

The official Linux x64 CLI is pinned to 8.30.1 and archive SHA-256
`551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`.
PRs scan `base.sha..head.sha`; merge groups scan `base_sha..head_sha` with a
complete checkout and verified identities. Complete graph traversal includes
side-branch commits, deleted incoming secrets and merge-only additions.
`--diff-merges=first-parent` changes merge diffs, not traversal. Invalid, missing,
shallow, unrelated or wrong-head checkouts fail closed. Queue bases must be
ancestors; diverged PR bases remain valid.

Configuration comes from the protected base, preserving all default rules and
the existing exact canonical security-ledger path AND complete 64-hex digest
line exception. No new exclusions, baseline, file-size skips, inline
`gitleaks:allow` comments or candidate ignore file can suppress findings.
External Git diff/textconv commands are disabled. Candidate files are read as
data; no candidate scripts, local actions, Nix evaluation, App credentials or
write tokens are used. Scanner output is discarded with full redaction and no
report upload. Only fixed status text and an exit code appear. Findings, scanner
errors and the 600-second timeout fail the job.

This conventional CLI workflow is an explicit exception to the repository's
devenv-only workflow command rule. Repository policy binds that exception to
the reviewed workflow's exact SHA-256; intentional edits must update the
binding and pass boundary fixtures. Other workflows retain their task contract.

## Dependabot admission integration requirement

The separate automatic-CI change in Maestro #185 compares only the triggering
workflow's bytes. Before integrating that admission path with this reusable
scanner, its companion must authenticate the complete immutable candidate diff:
only declared Cargo dependency files and SHA-only changes to existing protected
workflow/composite-action templates may pass. Changed reusable scanner commands,
privileges, scripts, scanner configuration, new workflows and incomplete file
inventories must fail closed. The scanner caller retains only `contents: read`
and passes no secrets. The companion is prepared separately; this scanner draft
does not claim #185 already enforces the transitive contract.

The twenty graph audit obligations remain. `source-security` now runs real
scanner allowlist fixtures and workflow boundary/range fixtures. The obsolete
whole-checkout scan and Python finding post-filter are removed. Upstream can
split large files inside a digest line, causing a false positive despite the
exact allowlist. The large-ledger fixture retains that behavior as a failure;
we do not broaden the exemption or filter findings against candidate content.
Resolving upstream fragmentation/performance remains debt, not a clean-scan
claim. A future incoming range that triggers it blocks until corrected.

The separately named daily/manual historical audit fetches branch, tag and PR
refs and scans all reachable history. Its failures and timeouts stay visible,
but it is outside the required verdict and is explicitly nonblocking historical
debt. No historical clean result is claimed or failure suppressed. Manual
history runs require protected main. No historical ledger or failed run is
rewritten.

Grype, complete runtime/distribution inventory, provenance, release
qualification, native policy drift checks and exact human decision authority
are unchanged. Protected-main release paths retain their existing authority
contracts; this change adds mandatory incoming scanning to the existing merge
gate. Hosted CI must still establish real engine behavior and complete Nix
validation before this implementation can be integrated.
