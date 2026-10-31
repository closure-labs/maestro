<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release continuation reconciliation wakeups

Decision reconciliation consumes successful CI, security, release and continuation
runs. A successful continuation resolver can also report no work: GitHub then
records only the successful resolver and the skipped `finalize` reusable job.
That completion previously repeated reconciliation even though it produced nothing.

The continuation-only read-only gate authenticates the event's exact run and
attempt using GitHub API responses. It checks repository IDs, workflow identity,
protected-main source ancestry, pinned reusable release workflow and a complete,
uncapped, unique job inventory bound to the same run, attempt and source SHA.
Only the exact two-job skipped-finalize shape suppresses a wakeup. Successful
context, security and product finalization preserve a real wakeup. Missing,
ambiguous or mismatched proof fails the gate rather than guessing. The same exact
attempt is re-read before emitting the scheduling result. Reruns do not substitute
a different attempt; delayed events remain usable when their source is an
ancestor of current protected main.

This is a scheduling hint, not a release receipt or authority decision. The
consumer still resolves and verifies complete evidence, byte provenance,
signatures and fresh live authority independently. No credential, authority or
mutable response cache is added. CI, security, direct/manual release, scheduled,
manual reconciliation and review wakeups retain their existing admission guards.
If proof cannot be read, an operator can retry the gate or use the existing manual
reconciliation path after diagnosing the failure; that path retains its checks.

The fixture performs six logical GETs and zero writes for either proven shape
(transport retry bounds remain the shared GitHub helper's policy). Production
continuation run 41242661247 attempt 1 used 99 runner-seconds and skipped finalize;
its reconciliation run 41242801212 used 202 reconciliation plus 120 health
runner-seconds. The new gate prevents those 322 downstream runner-seconds for
that shape, at the cost of its own checkout/Nix setup and six reads. Net hosted
savings require measuring the new gate after merge; 322 seconds is an avoided-work
bound, not a measured net reduction. No security ambiguity is resolved by this
change, and the direct CI-triggered reconciliation is preserved.
