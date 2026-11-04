<!-- SPDX-License-Identifier: Apache-2.0 -->
# Scheduled native official refresh and bounded reuse — inactive

Stacked on #230. This uses the existing daily Security maintenance workflow and
native refresh command. It adds one ordinary dependent job, not another workflow,
controller, risk ledger or polling loop. No flag or live setting changes here.

With both existing `MAESTRO_NATIVE_REFRESH_ENABLED` and
`MAESTRO_NATIVE_RELEASE_ENABLED` true, the native official job replaces the legacy
scheduled official-product loop. With either false, that loop remains unchanged.
The rolling native switch alone still preserves official coverage. This combined
activation must be coordinated only after #227–231, signed receipt availability,
consumer parity and independent review are verified. Defaults remain false.

GitHub's normal [`releases/latest` endpoint](https://docs.github.com/en/rest/releases/releases#get-the-latest-release) identifies the shipped stable product,
not a security decision or accepted finding. The existing bounded receipt loader
obtains its signer SHA as an untrusted scheduling hint, then requires the exact
standard release-workflow signature, source/signer ancestry, complete public asset
inventory and product binding before original CI/boot/inventory verification.
Missing receipt, changed pointer or incomplete evidence fails; no ledger/newest
approval selection, old-release rewrite or current-main fallback occurs.

The native job depends on rolling refresh. On a successful rolling job, protected
[GitHub job outputs](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/pass-job-outputs) carry only its verified original producer tuple and this run,
attempt, policy SHA and health expiry. If the official receipt names that same
exact authenticated producer, it reuses this invocation's signed rolling health
and performs no second inventory stage, restore, scan, attestation or artifact
upload. Different tuples are conservatively refreshed separately, even when some
bytes match; no deduplication on commit, version or ISO hash alone. This avoids
combining different proof contexts. There is no cross-invocation approval/health
cache, renewal or risk acceptance. Official pointer and main are rechecked.

If rolling fails, the dependent official job can still refresh the shipped
product, receiving no reuse metadata. A failure is not converted into workflow
success. Failed-only reruns cannot reuse outputs from an earlier attempt; use a
fresh complete run or the separate explicitly authorized manual official route.
Health from an overall failed workflow remains ineligible for publication under
the unchanged consumer check. Independent official scope uses its existing one-restore/one-scan path
and fresh Grype/RustSec databases with real shipped-file/npm checks. Per-job
45-minute and whole-command 40-minute budgets stay unchanged. A dependent runner
and its ordinary tool setup remain; fixtures do not establish hosted savings or
full-size headroom.

Different-product health uses the deterministic artifact name
`maestro-native-health-RUN-ATTEMPT-SOURCE`, signed by the same security workflow.
Consumers derive that exact name from their independently verified original
producer; a present malformed/expired/ambiguous scoped artifact rejects rather
than falling back. Without it, the existing flat health artifact remains supported
and its full signed original-proof/producer checks still apply. No newest artifact
or authority waiver is introduced. Same-producer reuse needs only the existing
rolling artifact. All existing full coverage, boot, NAR, freshness and live
per-publication findings-review gates remain independent.

## Qualification and retirement

Before activation, qualify both identical- and distinct-producer cases, failed
rolling refresh with successful official coverage, changed latest release/main,
scoped health consumption, late scanner/evidence failures and exact DB freshness.
Every publication still requires its own human findings-risk approval. The
nonpublishing gate trial remains separately authorized; this PR dispatches none.

After parity and action-time activation, remove the old official product
upload/ledger path and only then retire unused reconciliation/event/recovery
callers. Preserve historical records and the technical helpers still imported by
native verification, asset reconciliation and consumer code. Do not delete the
authority directory wholesale. Existing source-review protections/settings remain
subject to separate approval; this change does not replace them.

A first native receipt also requires an eligible release writer invocation.
GitHub documents that `GITHUB_TOKEN` cannot create releases targeting older
commits with workflow-file differences from default main. Bootstrap from fresh
exact-main qualification after the reviewed changes converge; do not widen
credentials to bypass that limit. The nonpublishing trial does not qualify
destination writes or accept the findings needed for an actual first release.
