<!-- SPDX-License-Identifier: Apache-2.0 -->
# CodeQL findings review

`Maintainer decision authority` checks the complete CodeQL SARIF results for
all four languages on the exact PR head and again on the exact merge-queue
commit. The existing required analysis checks still enforce successful scans.
The controller runs only protected-main code. Reports are data, never commands.
Rust scanner setup runs from a separate protected base/main checkout, including
its Nix dependency tree; candidate setup actions and toolchain helpers never run
in the scanner.
CodeQL receives only the candidate source root. Attempt-scoped artifact names
prevent reports from an earlier attempt satisfying a later retry.

Clean analysis needs no additional review beyond existing governance rules.
Every reported finding requires acceptance, including findings marked suppressed,
unchanged or informational. Scanner changes also require explicit acceptance even
if their report is empty. This prevents silently weakening the findings gate by
changing the analysis workflow, while allowing reviewed scanner upgrades.

When findings need review, the protected App first publishes a separate neutral
`CodeQL findings ready` check on the exact PR head. Its authenticated receipt binds
the PR, findings and scanner digest, run attempt, and complete artifact identities.
This check grants no authority and cannot release the required
maintainer-authority gate.
Inspect the linked run's four CodeQL artifacts and the PR changes, then submit a
normal GitHub **Approve** review. Its body may be blank; no command is required.

The review must be submitted strictly after GitHub records that report-ready
check's completion. Earlier approvals, including approvals in the same timestamp
second, do not accept an unseen report. Submit a new approval after the check is
visible. The displayed exact command remains a compatible explicit alternative:

    /maestro accept-codeql <current-PR-head-SHA> <findings-and-workflow-SHA256>

That one review satisfies both findings acceptance and existing code approval.
It must come from a currently eligible independent Super Admin with maintainer
access. A bot, PR author, ordinary comment, stale approval, or code-only
self-review cannot accept findings. Existing membership, identity, unresolved
changes-requested, dismissal, and exact-head checks still apply. This approval
accepts only this PR's CodeQL findings and analysis-workflow revision. It cannot
accept distribution vulnerability findings, authorize release/cache publication,
or waive any other CI gate.

The four scanner jobs retain fresh attempt-scoped reports. The Actions language
extraction job is named `Scan (actions)`; the existing required `Analyze (actions)`
context verifies all four completed native reports once, after the matrix finishes.
Its read-only candidate checkout grants no review authority and holds no App secret.
It authenticates artifact bytes, run/attempt and current scanner health. It rejects
an earlier same-SHA green App receipt until that receipt has been invalidated or
replaced by authority for the current attempt.

The protected App evaluates once per scan-start, scan-completion and review event.
Incomplete scans leave its required check pending and release the runner. Failed
or cancelled scans leave it blocked. Once reports are complete, the App authenticates
them and publishes the findings-ready check. A later eligible review event verifies
live approval and updates the same required authority check. No runner waits for
human approval, and a late review does not require rerunning successful scans.
Review edits and dismissals reevaluate authority as before.

The in-run native verifier has a 30-minute startup/execution cap. The App evaluator
has no scanner or human polling deadline; each wakeup evaluates current evidence
once. Its receipt still binds run, attempt, target, artifact IDs/digests and the
complete live review snapshot. Failed/cancelled scanners, changed reports and
dismissed reviews remain blocked. Scanner completion can now wake authority because
successful scanner execution no longer depends on human acceptance.

The authority also reevaluates the PR's current single-entry merge queue. The
same review applies there only when its findings and scanner identity are
identical to the original PR-head report accepted by that review. A newer
report-ready check posted after approval cannot substitute for the original
binding. Its original artifact identities are rechecked; fresh complete artifacts
are independently authenticated for a rerun or queue attempt. A changed head, changed finding, or changed scanner requires fresh
acceptance. An expired, missing, malformed, ambiguous or incomplete report never
counts as a clean scan. Rerunning CodeQL requires fresh artifacts for all four
languages; rerun all jobs rather than mixing old reports into a newer attempt.

No new token, App permission, required-check name, environment or live ruleset
change is introduced. The current App-bound required authority check enforces
this policy after the controller change lands on main. Candidate PR code never
publishes that authority check. Authenticated artifact ZIP digests, run/attempt,
revision, language inventory and bounded parsing are verified before approval.
SARIF text is not copied into public check summaries; the human reviews the
existing analysis artifacts directly.

## Validation and rollout

Normal approvals use a version-2 success receipt carrying the original report-ready
binding and accepting review ID. Explicit-command approvals retain version-1
receipts. The protected producer and report parser are already prepared on main;
this activation keeps their protocol, scanner job names and artifact names compatible.
The read-only in-run verifier changes from a human wait to a one-shot report check.
The App evaluator changes from scanner polling to scan/review wakeups when this
change lands on main; existing protected helpers can still validate this PR's reports
before merge. No privileged candidate code is executed by the App.

The exact workflow declaration `# maestro-codeql-findings-protocol: 1` opts a
candidate into the complete findings gate before activation merges. Once that
marker is on protected main, enforcement is mandatory even if a candidate
removes it. The trusted-main check cannot be disabled by a candidate. Unknown,
ambiguous, unreadable or byte-inconsistent protocol declarations fail closed.
This solves the producer/verifier bootstrap without a missing-helper fallback
or weakening a currently active gate. Do not activate before the protected report
producer and parser are present on the PR base. Rebase older open branches after
cutover so
their scanner workflow identity includes the activated protocol.


Run the bounded authority fixtures, including `test_codeql_findings.py` and
`test_check.py`, and the hosted full repository audit. Before declaring hosted
rollout complete, verify a clean PR, a findings-blocked PR, an eligible exact-head
acceptance, review dismissal, a changed finding and the merge-queue continuation
against real GitHub artifacts. Fixtures do not establish live GitHub transport or
workflow-event compatibility. No current findings are accepted by this change.
