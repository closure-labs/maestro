<!-- SPDX-License-Identifier: Apache-2.0 -->
# Queue runtime budget

This proposal changes the checked-in ruleset template, not the live GitHub
ruleset. Activate the queue response limit only through a separately approved
settings update after review, and verify its readback. The live setting observed
on 2026-11-09 was 180 minutes.

## Proposed limits

Use a 360-minute merge-queue response deadline. GitHub's public REST schema
allows 1–360 minutes; this is a bound, not a target runtime. Queue jobs use:

| Job | Minutes |
| --- | ---: |
| Plan CI | 30 |
| Execute repository validation | 90 |
| Bind repository audit | 20 |
| Equivalence | 30 |
| Retained evidence | 30 |
| Appliance | 120 |
| Installer | 30 |
| Inventory and scan | 60 |
| Boot | 15 |
| Release evidence | 15 |
| Verdict | 15 |

The longest conservative dependency path is 315 minutes:
plan → retained evidence → appliance → installer → inventory → boot → release
evidence → verdict. This counts all of those jobs even when routing skips some.
It leaves 45 minutes for runner queueing and scheduling between jobs. This margin
cannot guarantee a deadline during a GitHub outage. Audit and equivalence execute
in parallel; their completion remains required. The separate CodeQL and authority
workflows have shorter timeouts. Protected-main signing does not run in the merge
queue. Nothing is skipped or converted from failure to success to meet the budget.

The stage overrides apply only to merge-group runs. PR, dispatch and main retain
existing longer limits, allowing expensive cold preparation before a queue entry.
A stalled queue appliance now stops at two hours instead of running for four hours
past the old three-hour queue response window. An actual workload exceeding this
budget must be optimized or prebuilt with verified outputs, not granted an
unbounded queue deadline.

## Measurement basis and validation

Nine successful merge-group runs sampled from November 4–9, 2026 had maxima:
planning 7m05s, appliance 77m26s, installer 12m02s, inventory/scan 20m21s, boot
4m20s, repository audit 31m41s, equivalence 9m17s, release evidence 2m48s and
verdict 3m15s. The caps retain headroom above these observed maxima; these are not
proof of worst-case cold-cache duration.

Representative source runs:

- [Full appliance and installer path, 87 minutes](https://github.com/closure-labs/maestro/actions/runs/42445799958)
- [Longest sampled successful appliance build, 77m26s](https://github.com/closure-labs/maestro/actions/runs/41954086680)
- [Latest successful queue, 30m16s](https://github.com/closure-labs/maestro/actions/runs/42572054612)
- [Cancelled appliance after 233 minutes](https://github.com/closure-labs/maestro/actions/runs/42428789203)

The contract test evaluates the workflow dependency graph and proposed queue
limit. It rejects a growing critical path without scheduling margin, missing or
unknown timeout expressions, changed signing exclusion, and cyclic dependencies.
It also verifies that nonqueue build limits remain unchanged. Full hosted tests
remain required; observe the first real cold queue build after activation and
adjust measured caps rather than treating these estimates as a benchmark result.

Sources: [GitHub queue behavior](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue),
[REST schema](https://github.com/github/rest-api-description/blob/main/descriptions/api.github.com/api.github.com.json)
(`repository-rule-merge-queue.parameters.check_response_timeout_minutes`).
