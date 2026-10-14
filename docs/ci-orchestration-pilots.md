<!-- SPDX-License-Identifier: Apache-2.0 -->
# Maestro orchestration pilots

Both pilots retain the single appliance and its authoritative schema-v3 route.
They are opt-in and do not change required checks, vulnerability acceptance,
installer boot qualification, source identity, or artifact attestations.

## Audit and qualification overlap

Manual CI has `audit_overlap=false` by default. Setting it to `true` moves the
same complete `ci:repository-audit` task into an independent job after routing.
Qualification and its dependency scan can run while that audit finishes.
Protected-main signing requires audit success, and the required verdict rejects
failed, cancelled, skipped or missing pilot audits. Push, PR, merge-group and
scheduled CI keep their existing audit-before-qualification behavior.

The pilot can waste qualification work when the audit fails. It also adds a
runner and its checkout/toolchain startup, with potential concurrent cache and
CPU contention. A branch workflow dispatch is a safe hosted benchmark: it runs
real checks and qualification, cannot sign protected-main artifacts, and cannot
publish rolling or versioned releases. Compare serial and overlap dispatches on
the **same branch SHA**, with identical `validate_only=false`,
`force_artifact=true`, `release_candidate=false`, and opposite `audit_overlap`
values. Record cache warmth, queue delays, conclusion and every job/step timing;
sequential measurements still have cache-order effects. Do not use
`validate_only=true` to claim an observed qualification-overlap benefit.

## Event-driven release continuation

Ordinary release dispatch remains synchronous. The pilot requires both the
manual release input `event_continuation=true` and repository variable
`MAESTRO_RELEASE_CONTINUATION_ENABLED=true`. The variable is declared in
SecretSpec with default `false`; no new secret or Nix evaluation credential is
required. A disabled pilot request fails before version mutation.

The pilot prepares the same protected release version, then writes and uploads
one immutable `maestro-release-request` artifact **before** dispatching its
isolated CI candidate. Its schema binds repository, originating run ID, exact
source SHA, tag and version. Expiry is exactly 48 hours after the origin run was
created, including time spent preparing the version; 30-day artifact retention
is historical evidence rather than permission to resume an expired request.
The candidate title binds it to that origin. Dispatch returns immediately;
it does not hold a runner in `gh run watch`.

`Continue Maestro release` observes completion of both CI and Release Maestro.
This handles either completion order, but never executes the triggering source.
Its read-only resolver checks out protected main and fetches authoritative run
metadata. It verifies same-repository main dispatches, exact workflow paths,
request identity and lifetime, a single exact successful candidate, source
ancestry on current main, and the source's VERSION. Unrelated completions are
ignored. The existing release workflow revalidates those identities itself as a
reusable finalizer; its context accepts continuation only from a main
`workflow_run` event. Existing checksum, state, attestation, fresh scan, release
environment, final filename SBOM binding, and FIFO `maestro-publication` steps
remain in place. No PR receives new cache or publication permissions.

Every new release preparation, including the ordinary path, rejects another
unexpired pending pilot request before touching VERSION. A failed/cancelled
candidate or expired request permits an explicit fresh dispatch. Bounded
lookups fail closed if 300 recent runs cannot cover the complete 48-hour
window. API failures fail rather than imply absence or success.

Duplicate completion events serialize through `maestro-release` with
`queue: max`. A previously published exact-source tag skips scan and publication
and can finish the existing idempotent next-version advancement. A different
published source fails. Both release and rolling publication retain the shared
FIFO queue. If continuation fails, inspect the resolver logs and rerun its
original completion run while the request remains valid. Disabling the variable
stops new resolution; it does not withdraw a finalizer that already passed its
checks. Do not enable this pilot until its protected-main rollout is reviewed.

Fixtures exercise both event orders, unfinished/failed origins and candidates,
source/version/workflow/repository mismatch, expiry, multi-document request
rejection, ambiguous candidates, bounded lookup overflow, pending isolation,
disabled dispatch and preserved synchronous dispatch. They do not fake a
hosted release or replace attestation verification.

## Historical timing model

The following successful hosted runs provide observed baseline job and audit
step durations. The modeled DAG subtracts the audit step from the route job,
then joins audit and qualification-plus-security before signing. It assumes
unchanged job durations, 60 seconds of extra audit startup/queue overhead and no
additional contention or cross-job queue delay. It does not model signing,
publication, release preparation merges, or next-version merges.

| Actual baseline run | Audit step | Qualification | Scan | Modeled critical-path reduction | Modeled extra runner work |
| --- | ---: | ---: | ---: | ---: | ---: |
| [38615451476](https://github.com/closure-labs/maestro/actions/runs/38615451476) | 159 s | 736 s | 209 s | 159 s | 60 s |
| [38623241194](https://github.com/closure-labs/maestro/actions/runs/38623241194) | 189 s | 768 s | 202 s | 189 s | 60 s |

These are **modeled savings, not observed hosted pilot results**. Each checked-in
[benchmark report](benchmarks/maestro-overlap-38623241194.json) includes the raw
jobs response SHA256, observed durations and assumptions. Reproduce with the
native toolchain and a fresh unmodified GitHub jobs response:

```bash
gh api 'repos/closure-labs/maestro/actions/runs/38623241194/jobs?per_page=100' > /tmp/maestro-jobs.json
devenv shell -- python3 nix/automation/pilot-benchmark.py /tmp/maestro-jobs.json
```

Event continuation saves the idle release runner's CI watch period; it does not
shorten qualification or either protected VERSION merge. No hosted
continuation/release performance measurement is claimed. Fixtures confirm that
event dispatch omits the watch call. Benchmark it using fixtures and metadata
until a reviewed genuine release requests the pilot; do not manufacture or
publish a versioned release merely to measure it.
