<!-- SPDX-License-Identifier: Apache-2.0 -->
# Queue runtime budget

The workflow and ruleset template share a bounded merge-queue budget.
This refactor changes workflow scheduling, not the live ruleset.

## Current workflow limits

The checked-in queue response deadline remains 360 minutes. The live setting was
verified at 360 minutes during the 2026-11-24 CI review; this refactor changes no
GitHub settings. Queue jobs use:

| Job | Minutes |
| --- | ---: |
| Plan CI | 30 |
| Repository checks, including audit binding | 90 |
| Build, inventory, scan and boot | 225 |
| Release evidence | 15 |
| Verdict | 15 |

The conservative dependency path is 285 minutes: plan → qualification → release
evidence → verdict. Repository checks execute in parallel with qualification.
This leaves 75 minutes for runner queueing and scheduling inside the existing
360-minute deadline; it cannot guarantee a deadline during a GitHub outage.
CodeQL and authority workflows run independently. Signing runs only on protected
main, outside the merge queue.

The qualification cap combines the previous 120-minute appliance, 30-minute ISO,
60-minute inventory/scan and 15-minute boot limits. PR, dispatch and main get one
360-minute qualification job, within GitHub's hosted-job limit. No checks are
skipped to meet the budget. The consolidation removes intermediate NAR transport
and runner startup but needs hosted measurements before claiming a speedup.

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
It also verifies the consolidated nonqueue hosted-job limit. Full hosted tests
remain required; observe the first real cold queue build after activation and
adjust measured caps rather than treating these estimates as a benchmark result.

Sources: [GitHub queue behavior](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue),
[REST schema](https://github.com/github/rest-api-description/blob/main/descriptions/api.github.com/api.github.com.json)
(`repository-rule-merge-queue.parameters.check_response_timeout_minutes`).
