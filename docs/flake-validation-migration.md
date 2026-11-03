<!-- SPDX-License-Identifier: Apache-2.0 -->
# Single complete validation after the ordinary-flake trial

The temporary parallel trial is retired. The twenty obligations remain mandatory
in the required `Repository checks` job, whose native `ci:repository-audit` task
runs full `nix flake check`, including checks outside the legacy twenty-target
plan. The existing plan runner then records cached output identities for those
twenty obligations in the same Nix store; it does not execute them again. Its
per-target timings describe realization requests, not fresh test runtimes. Essential
appliance/installer qualification, boot verification, equivalence, scanners,
CodeQL, incoming Gitleaks, signing and the stable `Required CI verdict` remain.
No ruleset, review policy, publication flag, cache trust or findings acceptance
changes here. The local `ci:flake:validate` task remains a developer convenience;
there is no second automatic ordinary-flake workflow.

## Recorded parity, not a permanent extra layer

Run 41579547621 attempt 1 on PR merge candidate
`28e66d6e93f4a5b564437c9e3c80a59bedc5d741` produced comparison artifact
13206073571 (archive SHA-256
`96f4d78a04428645286eac2ff525f2b2adbb58a52284c5ea9f94af379aab9959`).
It matched all twenty exact attributes/outputs between complete validation and
independent graph realization, with no missing obligations or failures. The
comparison took 511.762 seconds. The ordinary flake workflow passed too. Required
boot evidence was verified-retained against exact media/verifier identity; this
does not claim that the PR executed a new VM boot. #212/#213 protected queue CI
subsequently passed. Final-main qualification and normal CI for this change still
must pass before treating the new producer contract as admitted evidence.

## Explicit evidence transition

The producer now emits a version 2 `ci-result.json` with
`validationMode: complete-audit`, exact full-audit/reference hashes, and successful
audit/qualification/scan results. Before emitting it, the existing bound-reference
validator checks all twenty results, exact output identities, zero failures,
producer/run/attempt and graph/plan hashes. The signed result does not claim a
comparison job ran. The duplicate realization job and its artifacts are removed;
the original complete audit manifest/timings remain for diagnostics.

Current signing and verdict require that explicit version 2 contract. Native
consumers recognize it strictly; historical version 1 proofs, including original
executed boot, retain their original requirement that comparison actually passed.
No skipped comparison is relabeled success. The full-flake pass is required
before the twenty-target receipt; evaluation-only `--no-build` is not used. Missing/mismatched full-audit proofs,
interrupted tests, stale attempts, scanner failures, boot substitutions and
integrity/freshness failures remain rejection cases.

The intentional guarantee delta is retirement of the independent routing
experiment after recorded parity. A second runner no longer reexecutes the same
checks as additional defense against a compromised first runner; the pipeline
relies on one trusted GitHub build/audit and its verified signed provenance.
This is ordinary CI trust, not a claim that builder compromise is impossible.
It is not removal of product/security tests.
The twenty obligations include metadata, CLI, evaluation, workflow/devenv/shell
contracts, automation/qualification/release fixtures, secretspec, operator and
repository policy, configuration, plan contracts, security fixtures, the runtime
security VM, Packer policy and source security. Additional flake checks such as generated-flake consistency, graph fixtures and
bootstrap/template wrappers are retained by the full-flake pass. Dependency
checks such as XO
file-restore/storage fixtures and the evidence-phase SBOM runtime test remain
covered by their existing derivation/job dependencies. Do not replace the real
installer boot contract with an ISO build.

Graph routing and historical publication consumers are separate staged work;
this change does not activate native publication or delete historical records.
The obsolete comparison command can be removed with the remaining graph/controller
consumers after their reference checks, rather than inventing another controller.
