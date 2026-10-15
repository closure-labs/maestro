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
GitHub suppresses downstream `workflow_run` events for candidates dispatched
with `GITHUB_TOKEN`, so a protected-main, request-bound candidate also sends an
explicit `workflow_dispatch` signal after its required verdict passes. Its
separate signal job has repository-read and Actions-write permissions only.
This handles either completion order, but never executes an untrusted triggering source.
Its read-only resolver checks out protected main and fetches authoritative run
metadata. It verifies same-repository main dispatches, exact workflow paths,
request identity and lifetime, a single exact successful candidate, source
ancestry on current main, and the source's VERSION. Unrelated completions are
ignored. The existing release workflow revalidates those identities itself as a
reusable finalizer; its context accepts continuation only from a main
`workflow_run` or explicitly bound `workflow_dispatch` event. Since dispatch
precedes completion of the signal job, an explicit resolver may poll the exact
origin and candidate under one 120-second completion deadline, including poll
API calls. This also handles the origin finishing second. Timeout fails; failure or cancellation
never becomes permission to publish. The whole candidate must succeed, including
the signal job. The originating release runner never waits for qualification.
Existing checksum, state, attestation, fresh scan, release
environment, final filename SBOM binding, and FIFO `maestro-publication` steps
remain in place. No PR receives new cache or publication permissions.

The final release filename receives new provenance and SPDX attestations. Before
either FlakeHub or GitHub publication, `release:attestations` verifies its local
checksum, protected-main source and reusable release-workflow signer digests,
subject filename/hash, and exact SPDX predicate. Checking out the requested source
does not change the caller's OIDC identity: if main advances and the caller or
workflow signer no longer matches the release source, publication fails closed.

The synchronous path still watches its exact CI candidate. If preparation first
merges a VERSION update, the originating dispatch queues one fresh-main release
dispatch with the same bump and ends without CI or publication. That new run sees
the already-prepared version and obtains its matching OIDC identity; the old run's
downstream jobs are skipped. Event continuation already obtains a fresh callback
context and does not take this synchronous restart path.

Every new release preparation, including the ordinary path, rejects another
unexpired pending pilot request before touching VERSION. A failed/cancelled
candidate or expired request permits an explicit fresh dispatch. Bounded
lookups fail closed if 300 recent runs cannot cover the complete 48-hour
window. API failures fail rather than imply absence or success.

To retire unpublished requests whose orchestration cannot continue, set the
repository variable `MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS` to a JSON array
of at most 16 unique positive integer origin IDs. For these two pilots use
`[38661176168,38669988679]`; use JSON integers, not quoted strings. The default
`[]` retires none. Scalars, booleans, floats, duplicates and wildcards are rejected.
First verify each trusted journal, absence of a published release and absence
of an active finalizer; record each reason and source. Both the preparation
guard and every resolver/finalizer reject exactly those requests while leaving
other requests eligible. Keep journals and logs, and remove each ID after its
own request's 48-hour expiry. Populate the plural variable before deploying the
new code; remove the obsolete singular `MAESTRO_RELEASE_RETIRED_REQUEST_RUN_ID`
variable after the new code is effective. Retiring a request does not revoke an
already-running finalizer, so do not skip the active-finalizer check.
Dispatch a new release at the fixed protected-main source and qualify it anew.
Do not use retirement to waive a source or attestation mismatch.

The first genuine pilot on 2026-10-15 UTC used request `38661176168`, source
`ceec1d7798a09ea6f31c4d1d264761e026335818`, version `3.0.0` and candidate
`38661464531`. The candidate passed audit, fresh media assembly and boot, scan,
signing and verdict, but its token-created completion emitted no continuation
event. The initial origin observer and ordinary-main observer correctly did
nothing; no versioned release was published. Retire that request before retrying
the corrected handoff, retaining the existing final source/signer gate.

The second request `38669988679` used source
`84a5a4b7c0736687e0132c5607f05ace200ec4b0` and candidate `38670283123`.
Its full audit, qualification, scan, signing and verdict passed, but GitHub's
implicit `success()` condition inherited the intentionally skipped overlap audit
and skipped the signal job. No versioned publication occurred. Signal delivery
and the callback's scan/publication joins now override implicit status inheritance
with `!cancelled()` and require each direct success result explicitly. Graph
fixtures cover skipped overlap/prepare ancestors and reject failed scans or
contexts; the live handoff still must pass before release.

Duplicate completion events serialize through `maestro-release` with
`queue: max`. A previously published exact-source tag skips scan and publication
and can finish the existing idempotent next-version advancement while main
VERSION still equals that release. Once VERSION has moved, late callbacks for
the old published release are ignored rather than starting stale advancement
jobs. A different published source fails. Both release and rolling publication retain the shared
FIFO queue. If continuation fails, inspect the resolver logs and rerun its
original completion run while the request remains valid. Disabling the variable
stops new resolution; it does not withdraw a finalizer that already passed its
checks. Do not enable this pilot until its protected-main rollout is reviewed.

Fixtures exercise both event orders, unfinished/failed origins and candidates,
source/version/workflow/repository mismatch, expiry, multi-document request
rejection, ambiguous candidates, bounded lookup overflow, pending isolation,
disabled dispatch and preserved synchronous dispatch. They do not fake a
hosted release or replace attestation verification.

## Observed hosted overlap pair

The same source SHA `d40f09a4282fadf873840ce9d9545ed550cbb445` was qualified
with two manual branch dispatches: [serial 38634526399](https://github.com/closure-labs/maestro/actions/runs/38634526399)
and [overlap 38634594909](https://github.com/closure-labs/maestro/actions/runs/38634594909).
Both forced fresh media and evidence with `validate_only=false`,
`force_artifact=true`, and `release_candidate=false`. The complete nineteen-target
audit, inventory assembly, real installer boot, current scan and required verdict
passed in both; signing and publication were skipped. Media/evidence fingerprints
and source identities matched. The separate overlap audit ran concurrently with
qualification and passed before qualification completed.

| Observed measure | Serial | Overlap |
| --- | ---: | ---: |
| First active job through required verdict | 20m21s | 19m04s |
| Summed active runner jobs | 20m11s | 23m22s |
| Initial dispatch/concurrency queue | 4s | 20m |
| Full qualification job | 520s | 654s |

The observed active path was 77 seconds shorter (6.3%), with 191 seconds more
runner work (15.8%). Initial queue is separate and contributes no claimed benefit.
This is one sequential pair on shared runners: cache order, setup, network and VM
variation are material. Qualification was slower in the overlap run, while route
and verdict were faster. These observations do not isolate a causal scheduling
benefit or justify enabling overlap by default. Keep the pilot opt-in and default
`false`. The existing historical models below remain models.

The [observed report](benchmarks/maestro-overlap-observed-38634526399-38634594909.md) and
[raw-fingerprinted timing summary](benchmarks/maestro-overlap-observed-38634526399-38634594909.json)
retain per-job/step timings and qualification input parity. They describe the
measured source before subsequent independent changes; later changes do not
retroactively receive this result. Event-driven release continuation remains
disabled by default and has fixture evidence only. No genuine release was
manufactured or published for this benchmark.

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
