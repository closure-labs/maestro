<!-- SPDX-License-Identifier: Apache-2.0 -->
# GitHub Free findings approval: inactive implementation

Dale approved fresh findings-specific approval per publication, including the
sole-maintainer and unobservable remove-and-restore limitations. This draft does
not accept any finding or activate publication. The existing legacy publisher,
required checks, ruleset and historical decisions remain unchanged.

## Implemented boundary

The inactive native cache workflow now prepares one bounded `maestro-findings-review`
artifact and job summary before its publisher can reach `findings-risk-review`.
The read-only preparation verifies original/fresh signed evidence; it never
restores a closure, scans again, obtains a writer credential or publishes. Its
context binds exact product/NAR roots, inventory, full raw and normalized finding
content, scan evidence, policy/verifier bytes, destination, workflow run and
attempt. Full findings accompany the digest so humans can inspect actual risk. The JSON
is streamed with a 64 MiB hard cap, matching the existing report size class,
rather than assuming complete exposure/context data fits a 1 MiB summary.
Approval explicitly accepts the displayed vulnerabilities, including high and
critical findings; ordinary PR approval is not risk acceptance.

The writer independently verifies evidence and requires the exact protected
pre-review context, one native human environment approval and current required
repository write access. Every existing mutation boundary rechecks live run,
environment, approval, access and context plus existing main/policy and evidence
freshness. Observed validation failure poisons that invocation's approval even
if access is restored. Evidence/integrity failure cannot be waived by risk review.
No old dedicated risk PR or JSON acceptance record grants authority on this path.
The unused native release library requires the same release-specific review;
there is no newly activated versioned-release workflow in this change.

Only a first-attempt, manual protected-main run is eligible. GitHub's documented
review-history response is run-scoped, without an attempt-specific approval
timestamp. Reruns therefore fail closed; a new invocation requires a fresh review
and exact remote-write readback before any retry. No automatic renewal occurs.
The thirty-day maximum remains an upper bound; evidence freshness and run lifetime
normally make authorization much shorter. No approval is shared between runs or
between cache and versioned release destinations.

Pre-review and writer jobs independently read bounded metadata/report evidence.
This is a deliberate trust handoff, not duplicate SBOM generation, scanning or
multi-gigabyte closure export. Writer closure restore/NAR verification remains
necessary at the actual distribution boundary.

## Exact future environment contract — not applied

The verifier requires an existing environment named `findings-risk-review`, with:

- One required human reviewer: Dale, user ID `52590374`.
- `prevent_self_review=false`, so the sole maintainer may initiate a publication
  and deliberately approve its findings. This is not second-person review.
- `can_admins_bypass=false`; approval cannot be bypassed through the deployment UI.
- Protected-branch deployment policy; the code additionally restricts the run to
  `refs/heads/main`, exact current policy SHA and the fixed publication workflow.
- Public repository identity `1127149753`; Free-plan protection availability must
  not be assumed after a public-to-private conversion.

Missing/changed settings reject the preparation/writer. Merely enabling the
existing native flag without configuring protections does not authorize a write.
The workflow remains under the existing disabled native-publication flag. No
new credential, permission grant, environment or ruleset change is made here.
Before activation, show fresh current/proposed settings for specific action-time
approval, independently review the exact head, and run a harmless protected gate
qualification. Existing release/publication environment and cache-secret placement
must be checked at that time; do not move secrets without explicit approval.

## Accepted limitation

A current-access lookup cannot detect access removed and restored between two
observations. Native review history cannot establish that continuity either.
The implementation rejects currently ineligible reviewers and observed loss;
it does not claim instantaneous invalidation or a race-free write. Fresh approval
for each publication avoids resurrecting a thirty-day approval for later releases.
No webhook service, access-history database or audit-API fallback is introduced.

## Validation and remaining qualification

Negative fixtures reject missing, rejected and ambiguous approvals. They verify
human identity and current permissions. Other cases reject a changed environment,
admin bypass, changed context, an unsupported run or attempt, expired evidence,
transport errors and writes without approval. The explicit
limitation fixture demonstrates that unobserved removal/restoration is
indistinguishable from uninterrupted access. A real bounded subprocess exercises
review JSON, summary and job-output production without accepting risk.

Normal hosted PR checks still validate all 28 public flake checks, twenty identity
obligations, scanner/inventory evidence and essential installer boot. These checks
do not validate a live environment approval: that requires separately approved
settings and a harmless nonpublishing hosted trial. Versioned release workflow
wiring and full-size writer qualification remain subsequent reviewed work.

References:
- [GitHub environment availability and reviewer behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [Native run review history](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run)
- [GitHub environment configuration and self-review](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
