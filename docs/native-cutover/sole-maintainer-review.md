<!-- SPDX-License-Identifier: Apache-2.0 -->
# Sole-maintainer review proposal

This proposal supersedes the immediate Phase A review settings in activation.md
and ruleset-20919039-plan.json. Those four stricter settings are a future migration
plan, not the current sole-maintainer contract. No live setting changes, release
activation, risk acceptance, or deployment is authorized by this document.

## Explicit code review while Dale is the only maintainer

GitHub does not allow a pull-request author to submit an APPROVED review on that
PR. It also cannot accept the last pusher's approval as independent last-push
review. We therefore keep GitHub's required approval count at zero, CODEOWNER
review and last-push approval off, and stale-review dismissal off. The existing
App-bound Maintainer decision authority check, CI/CodeQL, merge queue, deletion
and non-fast-forward protections, thread resolution and empty bypass list remain.
The declared policy matches those existing live settings rather than silently
turning on a rule that blocks the sole maintainer.

For Dale's own governed code PR, submit a **Comment** review through Review changes,
with the entire body `/maestro self-review FULL_HEAD_SHA` (replace FULL_HEAD_SHA
with the full current 40-character commit ID). This is an explicit application
review acknowledgement, not a GitHub native APPROVED review. The authenticated
review's commit ID must match too. Ordinary issue comments, approximate text,
old heads, a forged login, bot reviews and native self-APPROVED records do not
satisfy this exception. A new head needs a new review.

To revoke, submit a newer Comment review whose entire body is
`/maestro revoke-self-review FULL_HEAD_SHA`. A newer relevant revocation,
dismissal or changes-requested review supersedes the earlier acknowledgement.
Do not rely on deleting a review to record lasting revocation: use the explicit
new review. The check always reads the currently visible authenticated records.

The exception is limited to closure-labs/maestro and GitHub user ID 52590374,
login declarative-dale. That identity was verified from GitHub's existing #237
reviews. Current pinned Super Admins membership must consist only of that user;
active membership and maintain/admin repository access remain mandatory.
The complete paginated collaborators inventory, including outside and inherited
collaborators (`affiliation=all`), must show no other human with maintain/admin
role. Missing or unknown role information, duplicate identities, failed access,
truncation, changed roster or a second maintainer fails closed. Both team and
repository roster are re-read before acceptance; the normal check repeats its
review verification before emitting the result. No roster/approval cache is added.
A production read-token test remains required; do not assume the existing token
can read this endpoint or grant it new permissions silently.

The decision check opts in only for PRs without canonical historical security or
release decision proposals. Their bot-author and independent-review requirements
remain unchanged, as do the separate native publication findings-risk environment
and provenance/freshness/boot/coverage checks. Reviewing code accepts no findings
and authorizes no release. Agent-created PRs must still be genuinely Decider-
authored; do not impersonate Dale or change commit attribution to evade review.

## Security tradeoff

This permits one person to author and acknowledge their own code. It provides
intent, immutable head binding and a visible audit trail, not independent human
review or protection from compromise of that person's account. It deliberately
changes the former independent-code-review requirement for this exact temporary
case. Live team/role changes are checked during authority evaluation, but an
already successful GitHub check can outlive an access change until the next
review/queue/check evaluation. No continuous revocation or atomic membership-to-
merge transaction is claimed. The existing native risk-review limitations remain.

The policy-drift check still checks the full declared protection contract and
fails on mismatches; it is not disabled or made advisory. Its source expectation
change is security-relevant and needs explicit review before deployment.

## Transition when another maintainer joins

1. Add the person through separately authorized access management, with the
   intended repository maintain/admin access and eligible Super Admins membership.
   On the next authority evaluation, either expanded roster disables self-review;
   this does not wait for a date or silently accept an old acknowledgement.
2. Arrange genuine independent APPROVED reviews on exact current heads. Add the
   appropriate human to CODEOWNERS through ordinary reviewed source changes.
3. Prepare an independently reviewed PR removing the pinned sole-review exception,
   updating these tests and declaring one approval, CODEOWNER review, stale-review
   dismissal, and latest-push independent approval. Do not remove the App gate.
4. With explicit action-time approval, apply those four GitHub ruleset changes,
   preserving every unrelated live field. Coordinate the source/settings change
   so any temporary policy mismatch fails closed. Verify both maintainers can
   review each other's work and verify policy drift, queue checks and negative
   stale/self-review cases.
5. Only a separate complete native-consumer cutover may later consider retiring
   the legacy App authority gate. No bypass, findings acceptance, legacy ledger
   rewriting or automatic grant of access is part of this transition.

## Validation and deployment boundary

Before publication: review exact code, focused negative tests, the intended
security tradeoff and production collaborator-read capability. Publish only with
authorized Decider credentials as a draft. The proposal itself must use the
existing independent-review route (Decider author, Dale review), not its own new
exception. Normal hosted CI and fresh exact-head review precede merge. Merging
this controller/policy change activates the application-level exception and must
be explicitly authorized; this document does not grant that authorization.
