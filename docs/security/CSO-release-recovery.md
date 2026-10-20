Decision: APPROVED
Code review: APPROVED (local implementation only)
verdict_quality: substantive
Scope: post-implementation security review of release-recovery source changes in Maestro and xo-nixpkg.

The reviewed changes preserve the release trust boundaries. No P0, P1, P2 or P3 security finding was established. Independent QA now reports PASS in `docs/qa-reports/QA-release-recovery.md`, with 177 independent tests and no open implementation findings. The parent confirmed all final native audits exited 0. This approval covers local implementation security only; it is not a terminal ship approval. Deployment, publication, release approvals and external workflow dispatches remain governed by the parent’s final skill gate and protected repository policies. The parent owns the final gate and must require current QA, native checks on final commits, hosted checks, and existing human product authority.

## Reviewed snapshot

Compared isolated working copies against Maestro main `020ac05c7f660b1cdb8f8f194f79cbd3cdee7b8a` and xo-nixpkg main `cd6fc794cf6559d4d41e3adec62dce5a4b01df09`. This review covers executable changes and their regression tests, documentation and changelog entries. It does not attest a final commit that has not yet been made.

Executable-source fingerprints use SHA-256 of sorted `relative-path:sha256(file)` lines ending in a newline:

- Maestro: `ca5a83fc8bcb2ca08f581762604879bfe7e68584424a9cdfed2cc6871cb3b840`, covering `nix/automation/decisions/decision_authority.py`.
- xo-nixpkg: `ad095edb5a15b798d95528dfb79dac82691dcd0eba9e7f25d0b286b863f83d70`, covering the four changed workflow files and `ci/build-reuse.py`, `ci/decisions/decision_authority.py`, `ci/fetch-evidence.sh`, `ci/qualify-products.py`, `ci/reconcile-retained.sh`, and `ci/publication-controller.py`.

Source changes after these fingerprints require renewed review. Later documentation-only commits do not change the reviewed executable bytes.

## Findings

None established in the reviewed diff: P0:0 P1:0 P2:0 P3:0. This is a scoped code-review result, not a claim that either complete system is vulnerability-free.

## Trust and failure behavior

**Optional cache metadata does not authorize NAR import.** In xo-nixpkg `ci/build-reuse.py:155`, only an absent or empty historical PR association raises `UnavailableProducer`. The catch at `ci/build-reuse.py:255` continues to another candidate before signature verification or transport restoration. An invalid supplied association still fails the explicit provenance requirements at `ci/build-reuse.py:161`. Artifact/run substitution is rejected at `ci/build-reuse.py:254`, before the optional-metadata catch. A usable candidate still requires exact protected controller/workflow/launcher checks (`ci/build-reuse.py:178`), exact run/attempt attestation (`ci/build-reuse.py:197`), evaluated output matching (`ci/build-reuse.py:260`), authenticated restoration and physical store verification (`ci/build-reuse.py:278`). The optimization does not infer historical authority from a mutable current PR response. A legitimate historical launcher/workflow upgrade also becomes unavailable only after independent protected historical blob agreement (`ci/build-reuse.py:181`), exact attestation and output validation. `compatible_producer` at line 190 is called at line 270 before payload download or NAR import. Forged historical hashes, invalid signatures and malformed output structures remain fatal.

**Diagnostic response text cannot become logged authority.** Both authority modules are byte-identical. `nix/automation/decisions/decision_authority.py:47` and xo-nixpkg `ci/decisions/decision_authority.py:47` admit bounded numeric rate metadata and an allowlist of resource names; body inspection selects fixed categories only. Duplicate headers are suppressed at line 130. Raw error bodies, authorization headers, request IDs and query strings are not reflected. Reads retry only transient statuses 408, 429, 500, 502, 503 and 504, or transport/timeouts (`decision_authority.py:139`); 401/403 stop after one request. No stored response substitutes for current live authority.

**Run labels have an enforced input contract.** The publisher passes qualification run, attempt and publication purpose into the execution environment (`xo-nixpkg/.github/workflows/publish.yml:41`); qualification passes the requested attempt into its fetch step (`xo-nixpkg/.github/workflows/qualification.yml:49`). `ci/fetch-evidence.sh:11` validates the run, checks the expected attempt against current successful producer metadata before downloading, and binds `scans.json` to the resolved run/attempt at `ci/fetch-evidence.sh:29`. The result must still pass the publication gate or historical rescan verifier at `ci/fetch-evidence.sh:32`. Thus the stable names describe inputs enforced by the consumer; they do not create admission authority.

**A prior publisher success does not suppress fresh rescan or a newer handoff.** `ci/reconcile-retained.sh:70` first binds the selected evidence producer. Expiration handling at `ci/reconcile-retained.sh:73` runs before the completed-publication early exit at line 81. Expired observations request refresh even after a completed publication; only an active exact refresh suppresses that request. Publication deduplication uses run, attempt and release purpose. A newer attempt or rescan run has a different requested identity. The publisher independently authenticates evidence and checks live authority (`ci/publication-gate.sh:6`; `ci/decisions/publication.py:14`); scheduler state cannot admit a product.

**Reduced repeated work keeps required evidence.** `ci/qualify-products.py:45` builds each protector output once; line 68 copies that same assertion into the retained product evidence. Four profiles still scan against a freshly prepared database at `ci/qualify-products.py:38`, and each support root remains a scan subject and product root at lines 61–65. The separate prewarm concurrency group (`.github/workflows/prewarm-runtime.yml:10`) changes queue contention, not publication authority. Failed producer completions are excluded before reconciliation runs (`.github/workflows/security-reconcile.yml:28`).

**Historical reconciliation and remote recovery remain explicit.** Default reconciliation selects one latest successful main qualification (`ci/reconcile-retained.sh:14`); an explicit historical run uses the validated path at line 10. Completed exact publication suppresses automatic rescheduling while scans are fresh. Direct `publish.yml` dispatch remains available and reruns fetch, admission and the controller; no automatic remote-repair verdict is inferred from the scheduler. Dispatch discovery walks at most ten pages of 100 records created since the selected qualification began and fails closed if that bound is reached without a match (`ci/reconcile-retained.sh:40`; `docs/security-decisions.md:54`). For refresh, completed records are ignored so they cannot conceal an active refresh on a later page (`ci/reconcile-retained.sh:50`).

**Journal readback retries preserve acknowledged write identity and compare-and-swap.** `ci/publication-controller.py:31` validates commit/ref identity before it reaches diagnostics. The controller makes one non-forced update, validates the acknowledged ref and exact expected SHA at lines 87–97, then makes at most five reads under a four-second deadline at lines 98–124. It retries only the exact known prior head or confirmed initial absence. An unrelated head, malformed acknowledgement, non-fast-forward rejection, invalid response or API failure stops immediately. These reads cannot force an update or hide another writer. `Journal.complete` still permits a refreshed handoff for the same immutable product (`ci/publication-controller.py:126`), covered by a dedicated regression.

## Executed security checks

Targeted tests used the repository's native toolchains. Service interactions in these tests are isolated fakes; no remote mutation, workflow dispatch, token minting or publication occurred.

**Passed — xo-nixpkg cache, request binding, rerun and expiry regressions:**

```text
$ devenv shell -- python3 -m unittest tests.test_build_reuse.RestoreTests.test_missing_historical_pr_association_is_cold_build_miss tests.test_build_reuse.RestoreTests.test_invalid_supplied_pr_provenance_remains_a_hard_failure tests.test_build_reuse.RestoreTests.test_artifact_run_attempt_and_output_payload_substitutions_rejected tests.test_reconcile_retained.ReconciliationTests.test_fetch_binds_request_and_evidence_to_the_exact_successful_attempt tests.test_reconcile_retained.ReconciliationTests.test_expired_scan_dispatches_one_exact_refresh_even_after_completed_publication tests.test_reconcile_retained.ReconciliationTests.test_other_attempt_run_purpose_and_failed_publication_do_not_suppress
......
----------------------------------------------------------------------
Ran 6 tests in 1.524s

OK
```

**Passed — xo-nixpkg hostile diagnostic bodies/headers, retry isolation, permission failures and credential-error classification:**

```text
$ devenv shell -- python3 -m unittest tests.decisions.test_authority.Authority.test_github_api_invalid_diagnostic_headers_and_bodies_never_leak tests.decisions.test_authority.Authority.test_github_api_diagnostics_do_not_retain_previous_retry_response tests.decisions.test_authority.Authority.test_github_api_secondary_limits_and_permission_denials_never_retry tests.decisions.test_authority.Authority.test_github_api_invalid_credentials_category_does_not_echo_body
....
----------------------------------------------------------------------
Ran 4 tests in 0.011s

OK
```

**Passed — identical four Maestro diagnostic cases:**

```text
$ nix develop --accept-flake-config --command python3 -m unittest tests.decisions.test_authority.Authority.test_github_api_invalid_diagnostic_headers_and_bodies_never_leak tests.decisions.test_authority.Authority.test_github_api_diagnostics_do_not_retain_previous_retry_response tests.decisions.test_authority.Authority.test_github_api_secondary_limits_and_permission_denials_never_retry tests.decisions.test_authority.Authority.test_github_api_invalid_credentials_category_does_not_echo_body
....
----------------------------------------------------------------------
Ran 4 tests in 0.004s

OK
```

Maestro's initial `devenv shell` attempt stopped at SecretSpec's reason requirement before tests. The successful flake-native fallback above avoided SecretSpec bootstrap. Nix daemon access required sandbox escalation for native test execution; no approval review rejected these commands.

**Passed — new source credential-shape scan.** A Python scan of added `jj diff --from main --git` lines checked AWS access-key, GitHub-token, OpenAI-key and private-key marker patterns, reporting counts only:

```text
maestro added-diff credential-shape matches: 0
xo added-diff credential-shape matches: 0
```

**Passed — shared authority implementation parity:**

```text
$ cmp nix/automation/decisions/decision_authority.py ../maestro-release-recovery-xo/ci/decisions/decision_authority.py
[no output; exit 0]
```


**Passed — final historical-controller compatibility and pagination precedence regressions:**

```text
$ devenv shell -- python3 -m unittest tests.test_build_reuse.RestoreTests.test_authenticated_previous_controller_bytes_are_cold_build_misses tests.test_build_reuse.RestoreTests.test_previous_controller_still_requires_valid_attestation_and_receipt tests.test_build_reuse.ProducerTests.test_workflow_and_launcher_bytes_must_match_independent_protected_source tests.test_reconcile_retained.ReconciliationTests.test_matching_work_on_later_page_is_not_redispatched tests.test_reconcile_retained.ReconciliationTests.test_lookup_overflow_is_an_error_without_dispatch tests.test_reconcile_retained.ReconciliationTests.test_completed_refresh_on_first_page_does_not_hide_active_refresh_on_second
......
----------------------------------------------------------------------
Ran 6 tests in 1.815s

OK
```

An initial invocation used the nonexistent `ProvenanceTests` class selector and failed in test loading; the corrected command above passed. This was a reviewer invocation error.

**Passed — all targeted publication journal adversarial cases:**

```text
$ devenv shell -- python3 -m unittest tests.test_security.PublicationJournalTests
..............
----------------------------------------------------------------------
Ran 14 tests in 0.055s

OK
```

During review, an expired-scan fixture reproduced a page-1 completed refresh concealing an active exact refresh on page 2. Its observed output was an unwanted `qualification.yml` dispatch and `queried second page: False`. This operational duplication had no release-admission bypass. The final code restricts completed-success suppression to publication, and the exact cross-page refresh regression above now passes. No open finding remains from that reproduction.

## Limits and observations

No dependency versions, lockfiles, package manifests, network allowlists or credential scopes change in this diff. A new dependency/CVE audit, full repository/history credential scan, and unrelated framework compliance assessment were not run as part of this focused review. The local pattern lookup found no configured pattern library; it supplied no additional assurance. Parent-owned native repository audits and independent QA cover broader regression and policy checks; they are not replaced by the 34 targeted security tests. The parent reported the final Maestro declared audit, XO declared audit, and direct installed-Determinate XO check all exited 0. The earlier Nix remote BuildResult protocol error and fixture shebang portability problem were resolved before those final successful runs; they do not establish a release defect. These full-run exit statuses come from parent-owned execution sessions, not an independently repeated full audit by this reviewer.

The prior same-SHA publisher pass/fail/pass sequence does not prove a permission defect or rate limiting. The new typed diagnostics improve evidence for the next failure. The historic 403 root cause remains unproven until live response metadata establishes it.

Hosted qualification, complete publication and interrupted-publication recovery were not run by this reviewer. A local fake-backed test cannot establish GitHub token permissions, a usable live release approval, scanner database availability, cache transport performance, or the final public handoff. Those remain required external acceptance steps after the relevant approvals. No release should be described as verified from this report alone.

Final gate handling remains with the parent: QA must pass on current code, native audits must pass on the exact proposed commits, hosted checks must pass, and human product authority must still be checked live before publication.

## Report validation

**Evidence**: passed

```text
$ devenv shell -- node <great_cto>/scripts/lib/finding-evidence.mjs docs/security/CSO-release-recovery.md --strict
docs/security/CSO-release-recovery.md: 0 finding(s), 0 hypothes(e)s, 0 problem(s)
$ devenv shell -- node <great_cto>/scripts/lib/report-pii.mjs docs/security/CSO-release-recovery.md --strict
no reproduced values found
```

The validators were run from xo-nixpkg's native shell against this Maestro report; paths are abbreviated above. They check evidence structure and reproduced-value patterns, not release correctness.
