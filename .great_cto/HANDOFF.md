# Release recovery handoff

The user requested the great_cto skill and authorized considering simplification
and optimization of CI/CD, scans and caching. Work followed the bugfix path with
CI diagnosis, scoped implementation, architecture review, independent QA and
security review. Beads was unavailable; tasks.md is the phase tracking fallback.

## Review artifacts

- `docs/qa-reports/QA-release-recovery.md`: independent final QA and audit evidence.
- `docs/security/CSO-release-recovery.md`: security boundaries, tests and limitations.
- XO PR: https://github.com/closure-labs/xo-nixpkg/pull/112
- XO reviewed head: `d1432e0f6b29` (`fix/release-recovery`).

Original Maestro and xo-nixpkg working copies were preserved. Implementation lives
in isolated `/tmp/maestro-release-recovery-{maestro,xo}` checkouts, with jj commits.

## Completed locally

Both complete native repository audits exited zero. XO's full installed-Determinate
flake check also exited zero. Independent QA exercised unavailable/old-controller
cache fallback, native producer identity, all scheduling states, scan expiration,
pagination, journal acknowledgement/readback, immutable bytes and hostile inputs.

Default XO reconciliation processes one latest successful qualification rather
than up to twenty historical complete packets. Historical recovery stays explicit.
Fresh handoffs require their exact run and attempt; completion of an older scan
does not suppress a newer one. Prewarming no longer shares publication concurrency.
Three redundant supply-protector Nix requests are removed per qualification.
These are structural operation-count improvements, not measured hosted timings.

An initial final XO audit failed: its packaged older Nix client reported an
unrecognized remote BuildResult status. The installed Determinate client exposed
the underlying new fixture's `/usr/bin/env` dependency inside the Nix sandbox.
The fixture now uses its actual Nix-store Python interpreter. Both the complete
flake check and the declared native audit then passed. No check was skipped.

The existing journal PR #109 implementation was integrated on the new XO branch
after reproducing its failure. Its original remote branch/PR was not changed;
historical approvals do not transfer to the new combined head.

## Remaining external work

Hosted pull-request checks must finish on the exact final heads and protected
main reviews must succeed. Do not merge administratively, approve one's own
proposal, weaken a rule, or transfer an older approval to a changed head.

The invoked skill's fast path explicitly places `GATE:SHIP` between QA/security
and DevOps. Human ship approval and the native repository protections precede
merging changes that activate public release work. Runtime product/security
approvals remain separate from this code-review decision.

After those approvals, qualify fresh immutable products, verify live current
admission, and complete one release and a controlled interruption/recovery of the
same exact approved bytes. Confirm the existing journal, tags, cache identities,
release asset hashes and refreshed handoff; do not replace immutable published
bytes. None of these hosted publication/recovery actions has been run for the
new source. The historical shared-App HTTP 403 category remains a hypothesis
until the new safe diagnostics capture discriminating evidence.

Broader ledger-schema migration, metadata-only packet transport and retirement
of legacy report-mode scans were considered and deferred: each needs a separate
coverage/provenance migration proof. Existing historical evidence remains intact.
