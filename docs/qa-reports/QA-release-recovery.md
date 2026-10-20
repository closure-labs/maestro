Result: PASS

Local implementation QA and the final complete repository contracts pass. The reproduced pagination defect and fixture portability defect are resolved. Hosted qualification, publication and interrupted-publication recovery are `not_run`; this report does not close those gates.

Verdict quality: moderate. This review independently executed 177 distinct tests across the original and final modules, including three ephemeral acceptance tests. Final reuse (29), scheduler (14), security/journal (32), shell checks and the journal recovery reproduction pass. Coverage percentage, coverage delta, hosted performance and mutation score are unmeasured. Open implementation findings: P0: 0, P1: 0, P2: 0. Resolved findings: P2: 1.

## Resolved Finding QA-1: Completed Refresh Hid Active Refresh On Later Page

Severity: P2, resolved. The intermediate pagination revision returned `complete` immediately when page 1 included a successful exact refresh. The expired-scan caller dispatched unless the result was `active`, so it missed an active exact refresh on page 2 and duplicated work. Final XO `ci/reconcile-retained.sh:50` considers completed records only for publication lookup; refresh lookup continues seeking active requests. The added test at `tests/test_reconcile_retained.py:218` passes independently in the final 14-test scheduler run below.

**Evidence**: failed (captured before the fix; final regression now passes)

```text
$ nix develop --accept-flake-config --command python3 - <<'PY'
import importlib.util
s=importlib.util.spec_from_file_location('scheduler','tests/test_reconcile_retained.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
t=m.ReconciliationTests();t.setUp()
try:
    t.fixture['expiresAt']='2000-01-01T00:00:00Z'
    t.fixture['qualification_pages']=[[t.workflow('qualification',status='completed',conclusion='success')]+[t.workflow('qualification',run=122)]*99,[t.workflow('qualification')]]
    result,calls=t.run_scheduler()
    dispatch=t.dispatches(calls)
    print('exit:',result.returncode,'dispatches:',dispatch)
    assert not dispatch,'matching active refresh on page 2 must suppress another refresh even when page 1 contains completed exact refresh'
finally:
    t.doCleanups()
PY
exit: 0 dispatches: [['gh', 'workflow', 'run', 'qualification.yml', '--repo', 'closure-labs/xo-nixpkg', '--ref', 'main', '-f', 'qualification_run=123', '-f', 'qualification_attempt=2']]
AssertionError: matching active refresh on page 2 must suppress another refresh even when page 1 contains completed exact refresh
[exit 1]
```

## Scope And Plan

Reader: the maintainer deciding whether to send these changes through protected-main and release approval.

Reviewed all implementation `jj diff --from main --git` changes in `/tmp/maestro-release-recovery-maestro` and `/tmp/maestro-release-recovery-xo`, based on `020ac05c` and `cd6fc794`. Final executable changes are in Maestro `fba69f17` and XO `d1432e0f`; QA documents follow in the working copy. The brief requires optional-cache recovery, bounded authority diagnostics, reduced repeated scheduling/build work, exact product/run/attempt admission, and interrupted journal checkpoint recovery. No database migration or appliance policy changed. No separate architecture requirements checklist or Gherkin feature file exists in this change; the scenarios below provide acceptance traceability.

The QA plan was source review, repository-native focused tests, shell checks, independent adverse-input acceptance, and inspection of the already-running repository audit logs. Full audits were not duplicated. Hosted dispatch, credential creation, publication and external mutations were outside this independent review's authorization.

## Acceptance Traceability

| Requirement / Given-When-Then Scenario | Actual Mechanism And Evidence | Result |
| --- | --- | --- |
| Given an historical PR run with absent associations, when reuse is attempted, then another authenticated candidate or a cold build remains available. | XO `ci/build-reuse.py:155` treats only absent/empty PR associations as `UnavailableProducer`; `ci/build-reuse.py:254` checks run/attempt substitution before catching that exception. `tests/test_build_reuse.py:381` proves a miss without import; `:397` proves continuation to run 101; `:425` keeps supplied malformed/ambiguous provenance fatal. | passed |
| Given an authentic old protected controller, when current launcher/workflow bytes have changed, then the old cache becomes unavailable without importing it or hiding forged evidence. | XO `ci/build-reuse.py:181` verifies historical protected blobs; `:259` verifies exact attestation; `:264` validates every output before `:270` checks current-controller compatibility. Tests at `tests/test_build_reuse.py:438` prove an authenticated historical miss; `:452` proves an invalid signature or malformed output remains fatal. | passed |
| Given temporary authority API failure, when reading live authority, then retries stay bounded and permanent denials stay closed. | Maestro `nix/automation/decisions/decision_authority.py:94` bounds fresh GETs to three attempts with one- and two-second sleeps. At `:139`, HTTP 403 is an immediate failure. Both repositories' authority suites pass timeout/transport/408/429/5xx recovery, exhaustion, malformed output and permanent-error cases. | passed |
| Given private headers/body content, when authority fails, then diagnostics disclose only typed values and fixed categories. | Both authority implementations' `api_failure_details` at line 47 limits body inspection to 8192 bytes, validates numeric bounds and resource enum, suppresses duplicate diagnostic headers and never reflects raw messages. Tests assert complete exception strings for rate limits, permission denial, invalid credentials and malicious/oversized input. | passed |
| Given one successful qualification, when the default scheduler runs, then it handles one packet and keeps security and release decisions distinct. | XO `ci/reconcile-retained.sh:14` selects one latest successful run; `:21` checks repository/workflow/event/status/SHA; `:87` and `:90` retain both decision calls. `tests/test_reconcile_retained.py:100` asserts one download and one publication dispatch containing run 123 / attempt 2. Manual history and empty discovery pass at `:170`. | passed |
| Given active/successful exact publication and fresh scans, when scheduling, then duplicates stop; another run, attempt, purpose or failed publication does not suppress work. | XO `ci/reconcile-retained.sh:38` matches repository, workflow path, main branch, dispatch event, SHA shape and exact workflow display title. `:81` checks release/run/attempt. Tests at `tests/test_reconcile_retained.py:114`, `:124`, `:136` and independent acceptance cover all five active states and wrong identities. Page-2 matches and bounded overflow pass at `:204` and `:211`. | passed |
| Given expired scans, when an exact publication previously succeeded, then fresh scanning is still required. | XO `ci/reconcile-retained.sh:73` handles expiry before completed-publication suppression and dispatches an exact run/attempt refresh. Tests at `tests/test_reconcile_retained.py:147` and `:158` prove this ordering and active-refresh suppression. Lookup errors fail before dispatch at `:196`; QA-1's cross-page refresh regression passes at `:218`. | passed |
| Given a run rerun, when a publication or refresh request names the older attempt, then fetching rejects it before admission. | XO `.github/workflows/publish.yml:45` and `.github/workflows/qualification.yml:53` forward `QUALIFICATION_ATTEMPT`; `ci/fetch-evidence.sh:16` compares it to current successful metadata, and `:29` binds downloaded `scans.json` producer run/attempt. Tests at `tests/test_reconcile_retained.py:235` prove rejected requests never call the publication gate. Independent acceptance also exercises the rescan branch. | passed locally; hosted workflow input evaluation not_run |
| Given four profiles, when qualifying, then each support output is resolved once while exact assertion bytes remain in the product. | XO `ci/qualify-products.py:46` resolves the support path used again by `:68`; the deleted second build call removes three invocations. `tests/test_profile_database.py:203` asserts eight total build requests, each supply-protector output once, matching copied/flattened assertion bytes, asset hashes and roots. Other tests retain four independent scans and failure cleanup. | passed |
| Given failed producer completion or read-only prewarming, when jobs are scheduled, then failed completions do not wake reconciliation and prewarming does not occupy the publication group. | XO `.github/workflows/security-reconcile.yml:28` checks workflow-run success; `.github/workflows/prewarm-runtime.yml:11` uses a separate concurrency group. All changed workflow command bodies continue to invoke declared devenv tasks. | source review passed; hosted scheduling not_run |
| Given an acknowledged journal write and one stale readback of the exact known prior head, when recording a checkpoint, then bounded retries accept the new head while unrelated writers remain fatal. | XO `ci/publication-controller.py:93` authenticates the acknowledgement, `:98` bounds readback to four seconds / five attempts, `:117` rejects every unexpected head, and `:88` keeps `force: false`. `tests/test_security.py:363` covers known-prior recovery; `:372`, `:384`, `:422`, `:440`, `:453`, `:471` cover exhaustion, hostile head, CAS rejection, deadline, timeout and acknowledged creation. Fresh handoff at `:518` still saves a new identity. | passed locally; hosted interruption/recovery not_run |

## Independently Executed Commands

Initial unprivileged native invocations failed before tests because Nix could not open read-only `~/.cache/nix/fetcher-locks` files. The same native commands then ran with approved sandbox escalation. No credentials were read or changed.

**Evidence**: passed

```text
$ cd /tmp/maestro-release-recovery-xo
$ nix develop --accept-flake-config --command bash -c 'python3 -m unittest discover -s tests -p test_build_reuse.py -v && python3 -m unittest discover -s tests -p test_profile_database.py -v && python3 -m unittest discover -s tests -p test_reconcile_retained.py -v && python3 -m unittest discover -s tests/decisions -p test_authority.py -v && bash -n ci/reconcile-retained.sh ci/fetch-evidence.sh && shellcheck ci/reconcile-retained.sh ci/fetch-evidence.sh'
Ran 27 tests in 0.041s
OK
Ran 5 tests in 0.037s
OK
Ran 11 tests in 4.086s
OK
Ran 47 tests in 0.253s
OK
[exit 0; bash -n and shellcheck emitted no findings]

$ cd /tmp/maestro-release-recovery-maestro
$ nix develop --accept-flake-config --command python3 -m unittest discover -s tests/decisions -p test_authority.py -v
Ran 47 tests in 0.250s
OK
[exit 0]
```

**Evidence**: passed

```text
$ cd /tmp/maestro-release-recovery-xo
$ nix develop --accept-flake-config --command python3 - <<'PY'
[ephemeral unittest subclass of tests/test_reconcile_retained.py fixtures;
 five active statuses, eight invalid producer fields, three rescan-attempt cases]
PY
test_all_active_states_suppress_exact_publication (__main__.IndependentAcceptance.test_all_active_states_suppress_exact_publication) ... ok
test_selected_producer_metadata_must_match_trusted_workflow (__main__.IndependentAcceptance.test_selected_producer_metadata_must_match_trusted_workflow) ... ok
test_rescan_fetch_also_rejects_wrong_request_and_native_attempt (__main__.IndependentAcceptance.test_rescan_fetch_also_rejects_wrong_request_and_native_attempt) ... ok
Ran 3 tests in 1.227s
OK
[exit 0]
```

These 16 extra subcases exercise actual Bash/jq and fake service executables. They do not contact GitHub or prove hosted authorization. The rescan verifier is a no-op fixture; this check measures the fetch leaf's attempt gate, not attestation verification itself.

Final code also includes the historical-controller compatibility fix and publication-journal recovery fix. I reviewed both diffs and independently reran every affected test module after the parent declared source writes complete.

**Evidence**: passed

```text
$ cd /tmp/maestro-release-recovery-xo
$ nix develop --accept-flake-config --command bash -c 'python3 -m unittest discover -s tests -p test_build_reuse.py -v && python3 -m unittest discover -s tests -p test_reconcile_retained.py -v && python3 -m unittest discover -s tests -p test_security.py -v && bash -n ci/reconcile-retained.sh ci/fetch-evidence.sh && shellcheck ci/reconcile-retained.sh ci/fetch-evidence.sh && python3 /tmp/maestro-journal-repro.py'
Ran 29 tests in 0.076s
OK
test_completed_refresh_on_first_page_does_not_hide_active_refresh_on_second (test_reconcile_retained.ReconciliationTests.test_completed_refresh_on_first_page_does_not_hide_active_refresh_on_second) ... ok
Ran 14 tests in 10.496s
OK
Ran 32 tests in 6.236s
OK
Acknowledged write survived known prior-head visibility; immutable checkpoint preserved.
[exit 0; bash -n and shellcheck emitted no findings]
```

The unchanged profile/database module (5 tests), XO authority module (47 tests) and Maestro authority module (47 tests) retain their earlier independent passing runs. The distinct final persisted test total is 174 (29 + 14 + 32 + 5 + 47 + 47); the three additional ephemeral acceptance tests bring this review's distinct passing test count to 177. Repeated runs are not added to that count.

The parent's full Nix-sandbox check exposed a fixture portability problem: generated fake executables used `/usr/bin/env`, absent in that sandbox. Final `tests/test_reconcile_retained.py:32` uses `sys.executable` to bind the already-running store interpreter. I reviewed that fixture-only correction and independently reran all 14 scheduler tests after it.

**Evidence**: passed

```text
$ nix develop --accept-flake-config --command python3 -m unittest discover -s tests -p test_reconcile_retained.py -v
Ran 14 tests in 10.583s
OK
[exit 0]
```

## Repository Audit Evidence

The parent launched the complete repository audits. I inspected their terminal logs rather than duplicate the runs. The parent confirmed final Maestro session 15195, XO direct flake session 63038 and XO declared-task session 78837 each exited 0. These are parent-run full-contract results, distinct from my independently executed focused tests.

**Evidence**: passed (terminal logs inspected independently; process exits supplied by the parent who ran the commands)

```text
$ cd /tmp/maestro-release-recovery-maestro
$ SECRETSPEC_REASON='Validate final release-recovery repository contracts' devenv tasks run ci:repository-audit > /tmp/maestro-release-recovery-maestro-audit.log 2>&1
[parent observed exit 0]
$ tail -n 14 /tmp/maestro-release-recovery-maestro-audit.log
  maestro-packer-policy> The configuration is valid.
  maestro-source-security> 11:09PM INF scanned ~13271048 bytes (13.27 MB) in 7.34s
  maestro-source-security> 11:09PM INF no leaks found
{}

$ cd /tmp/maestro-release-recovery-xo
$ nix flake check --accept-flake-config --no-write-lock-file > /tmp/maestro-release-recovery-xo-determinate-audit.log 2>&1
[parent observed exit 0; nix resolved to /nix/store/2wwfgn6vzryiqrrskp7k9jxkgc7im64f-determinate-nix-3.23.3/bin/nix]
$ tail -n 12 /tmp/maestro-release-recovery-xo-determinate-audit.log
✅ checks.x86_64-linux.repository
✅ checks.x86_64-linux.automation-fixtures
✅ checks.x86_64-linux.native-runtime-cleanup
✅ checks.x86_64-linux.repository-policy
✅ checks.x86_64-linux.yarn-cache-fixtures
✅ checks.x86_64-linux.plan-runner-fixtures
✅ checks.x86_64-linux.application-composition
✅ checks.x86_64-linux.ci-runtime-fixtures
✅ checks.x86_64-linux.classifier-fixtures
✅ checks.x86_64-linux.source-update-fixtures

$ devenv tasks run ci:repository-audit > /tmp/maestro-release-recovery-xo-audit.log 2>&1
[parent observed exit 0]
$ tail -n 14 /tmp/maestro-release-recovery-xo-audit.log
  running 0 flake checks...
  all checks passed!
{}
```

The initial final-XO declared-task attempt had failed after 27.5 seconds with `Invalid BuildResult status [control byte] from remote`. The parent diagnosed the packaged Nix 2.34.9 client as masking the sandbox fixture failure. The installed Determinate client exposed the missing `/usr/bin/env` fixture dependency; the interpreter correction above fixed it. The final direct full contract and subsequent declared-task retry both passed. The retry reused already-realized final checks, which explains its `running 0 flake checks` line. No gate was skipped or treated as passing on the initial protocol error.

## Limits And Release Gates

Coverage percentage and before/after delta: unmeasured. Mutation score: unmeasured; no mutation run performed. Test reliability: the reproduced intermediate QA-1 assertion failed once and its final regression passes; all other focused executions passed. Runtime/build wall-time savings, p95 and CI cost: unmeasured. The source change and fixture prove three fewer Nix build invocations; they do not establish three fewer derivation builds or a hosted time saving. Default reconciliation now downloads at most one packet per tick rather than up to 20.

Scheduler suppression now searches up to ten pages of 100 dispatch records created since the selected qualification began, as documented in XO `docs/security-decisions.md:54`. A full tenth unmatched page fails scheduling with an explicit recovery diagnostic; it does not infer an empty queue. The final 14-test suite proves a page-2 publication match, fail-closed overflow and the QA-1 refresh precedence fix. An omitted manual attempt produces an `attempt current` title, so it deliberately does not satisfy exact-attempt suppression.

The original HTTP 403 cause remains unproven by these tests. New diagnostics distinguish rate-limit and permission categories on the next real failure. Bounded retries do not make a permanent 403 succeed. This is an explicit hosted verification gap, not a newly reproduced code defect.

Hosted qualification, exact-commit protected-main checks, complete release, remote artifact identity verification and interrupted-publication recovery: `not_run`. Appliance rebuild/deployment and destructive recovery: `not_run`, outside this code-only QA scope. Rollback drill: `not_run`; this change modifies automation rather than migrating deployed appliance state. No CIS, load or endpoint performance gate applies to these changed leaves.

Local implementation acceptance and complete final repository audits pass. Public release completion still requires the protected repository checks, live human product authority and hosted release/recovery evidence identified in the brief.

## Report Checks

**Evidence**: passed

```text
$ nix develop --accept-flake-config --command bash -c 'node /var/home/dale/projects/skills/great_cto/scripts/lib/pattern-lookup.mjs --role review; node /var/home/dale/projects/skills/great_cto/scripts/lib/finding-evidence.mjs /tmp/maestro-release-recovery-maestro/docs/qa-reports/QA-release-recovery.md --strict; node /var/home/dale/projects/skills/great_cto/scripts/lib/prose-slop.mjs /tmp/maestro-release-recovery-maestro/docs/qa-reports/QA-release-recovery.md --quiet'
=== KNOWN PATTERNS for archetype=unknown stack=unknown ===
  no pattern library yet (/var/home/dale/.great_cto/global-patterns) — run /crystallize after the next incident to start one
/tmp/maestro-release-recovery-maestro/docs/qa-reports/QA-release-recovery.md: 0 finding(s), 0 hypothes(e)s, 0 problem(s)
[exit 0; prose checker emitted no findings]
```
