<!-- SPDX-License-Identifier: Apache-2.0 -->
# GitHub GET retries and admission request volume

Maestro adapts the validated pure helper from xo-nixpkg PR #212, exact commit
`109656e3767982c4adf9f766d1b7d719975e37ff`. The helper is copied unchanged into
`modules/ci/authority/_source/decisions/github_retry.py`; its deterministic tests
run with the existing authority fixture discovery. The existing Maestro bounded
GET parser, typed errors, diagnostics and process supervisor remain the adapter.

Each GET has at most three attempts within 45 monotonic seconds, shortened by
its enclosing operation budget. Each transport receives at most 30 seconds and
only the time remaining. Retry-After integer seconds or an aware HTTP date and
future primary-reset timestamps set minimum delays. Positive jitter adds
0.05–0.25 seconds. Missing or stale primary reset, malformed or duplicated
Retry-After, or a delay that cannot fit fails closed. Secondary throttling without
an explicit delay requires at least 60 seconds, so the default budget defers it
to scheduling. Repeated timeouts share the same deadline rather than receiving
three independent 30-second windows.

403 retries require explicit throttle evidence or a valid server delay. An
explicit integration permission denial remains terminal even when a response
also carries quota headers. Other unrelated 4xx remain terminal. Existing
transient GET handling retains bounded retries for transport/timeouts, 408,
500, 502, 503 and 504. Invalid framing/JSON, oversized responses and killed
transports still fail immediately. Errors retain only existing typed diagnostics;
response bodies, credentials and arbitrary header values remain suppressed.
Mutations continue to use their existing one-shot/readback behavior. The helper
does not store responses or authority conclusions.

## Measured admission reads

The deterministic admission API fixture records every requested endpoint. The
baseline is Maestro main `1a8ddae0cf86564026c03f8d3f89902f71e84524`; each case
models one associated PR, one changed file, and one page per collection.

| Successful operation | Baseline GETs | Updated GETs | Immutable workflow GETs |
| --- | ---: | ---: | --- |
| Cargo manifest change | 10 | 10 | 1 → 1 |
| Pin update in the triggering CI workflow | 11 | 10 | 2 → 1 |

The Actions case saves one GET (9.1% of that fixture's reads). It reuses only the
already validated workflow at the same immutable head within that one operation.
Changed-file enumeration remains bounded, unknown paths still fail closed, and
other changed workflows are independently checked. The fixture executes twice
to prove operation boundaries discard the reuse state. Live run, PR and protected
main reads each remain twice per operation. Rules, reviews, membership,
permissions, required checks and final authority paths receive no caching or
read removal. These fixture counts are not a production-wide traffic estimate.

Existing publication metadata batching and request-attribution diagnostics remain
in place. This change is limited to the common authority GET adapter and the
measured duplicate immutable read in CI admission.

[Validated source](https://github.com/closure-labs/xo-nixpkg/tree/109656e3767982c4adf9f766d1b7d719975e37ff)
and GitHub's [rate-limit guidance](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
define the upstream retry behavior. Heavy Nix evaluation, builds and qualification
remain hosted CI responsibilities; local fixtures use fake clocks and transports.
