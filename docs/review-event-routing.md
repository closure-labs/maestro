<!-- SPDX-License-Identifier: Apache-2.0 -->
# Verified review-event routing

GitHub review workflow runs can omit `pull_requests`. Previously each such
wakeup enumerated all open main-targeting PRs and republished their authority
checks. The optimization applies only to `pull_request_review` runs whose
canonical GitHub metadata supplies a positive run ID/attempt, active collector
workflow ID/path, repository IDs, immutable head SHA and source branch.

The protected controller asks GitHub for the exact commit's PR association.
Only one association qualifies. A fresh canonical PR read must agree with the
number, open/main state, base and source repository IDs/names, SHA and branch.
The collector run is reread immediately before accepting that routing result;
changed attempt, workflow, source or event metadata discards it. All routing
inputs come from authenticated API responses, rather than event text,
candidate artifacts, author strings or branch naming conventions.

Legacy/missing metadata, fork sources, multiple or capped associations, unknown
workflow identity and changed PR bindings retain the existing global fallback.
An ambiguous list does not cause a new per-associated-PR walk. Transport and
permission failures propagate; they are not retried through a fallback identity
or alternate route. Untrusted collector origin still fails before any writes.
Other collector event kinds and explicit GitHub PR associations retain their
existing behavior.

Routing selects work only. The existing checker independently rereads the PR,
changed files, current reviews, membership and permissions, repeats authority
after packet/tree validation, and rereads the PR before check publication. Live
main/policy/rules/required-check paths remain unchanged. The routing result and
all API responses are discarded between operations; no authority conclusion is
cached. Review submissions, edits and dismissals still receive fresh checks.

## Measured request counts

`test_review_routing.py` executes the existing full checker against fake APIs,
with one-page inventories and a unique association to one of the open PRs.
The comparison uses the original global path with absent association metadata.

| Open PRs | Governed GETs: global → routed | Ordinary GETs: global → routed | Check writes: global → routed |
| --- | ---: | ---: | ---: |
| 1 | 28 → 30 | 8 → 10 | 1 → 1 |
| 5 | 132 → 30 | 32 → 10 | 5 → 1 |
| 10 | 262 → 30 | 62 → 10 | 10 → 1 |

At ten governed PRs this saves 232 GETs and nine unrelated check writes for one
verified review wakeup; at one PR verification costs two extra reads. Ambiguous
or missing routing still incurs the complete global work. These are fixture
counts, not repository-wide traffic forecasts.

Tests also exercise missing/spoofed associations, repository/workflow identity,
legacy metadata, ambiguous inventories, permission failures, revoked authority,
collector rerun/head races, late review/head changes and operation isolation.
A real collector inspected during design was run `41165484526`: GitHub recorded
workflow ID `390056787`, source branch `api-request-budget`, and head
`efc1997019bf71e5191641aa43e100a7bcfdd087`, whose canonical association is PR #188.
The PR is now closed, which correctly requires fallback rather than treating
that historical observation as current routing or authority.
