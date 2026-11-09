<!-- SPDX-License-Identifier: Apache-2.0 -->
# Native workflow retirement

This source cutover removes legacy release-publication and release-continuation
controllers, legacy jobs in release/publication/security/consumer workflows,
the CI continuation callback, and automatic proposal reconciliation. It does not
change repository variables, environments, rulesets, credentials or human approvals.

## Retained responsibilities

- `release.yml`: explicit exact native release review and gated finalization;
  separate nonpublishing full-size qualification. Native release enable flag and
  exact findings-risk-review approval remain required.
- `publication.yml`: explicit native cache review/publication and read-only gate
  qualification. Cache writes retain their separate enable flag and review.
- `security.yml`: daily current-main and official-release inventory refresh,
  signed health evidence, read-only drift reporting and same-invocation reuse.
  Scheduled reads no longer depend on rollout flags. Manual refresh uses exact identities.
- `consumer-probe.yml`: weekly signed official ISO/SBOM/attestation and cold-cache
  integrity checks. This grants no current-health, findings or publication authority.
  Explicit manual fresh-policy verification remains separate.
- `decisions.yml`: hourly/protected-producer health reporting, no reconciliation
  or publication. Maintainer event collection and App-bound authority stay independent.

## Historical evidence and limits

`automation/decisions/` is unchanged. Legacy library readers and archived workflow
snapshots in `modules/ci/authority/_tests/fixtures/retired-workflows/` preserve audit
regression coverage; snapshots are test data, not runnable Actions workflows.
This retires hosted routing, not every historical library or operator command.
No historical findings are accepted. New reviews bind changed policy source and
require new exact human approval.

Original inventory expiry still blocks refresh and weekly verification. There is
no unverified release-only fallback or indefinite retention claim. Durable evidence
renewal needs a separately reviewed change before retained artifacts expire.

Hosted full repository checks and a full-size nonpublishing consumer trial remain
required. Focused local tests do not establish Nix packaging parity or real public
cache availability. Weekly checks may correctly fail if cache roots have never
been published; enabling that writer remains a separate action.
