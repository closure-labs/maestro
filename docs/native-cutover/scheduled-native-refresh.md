<!-- SPDX-License-Identifier: Apache-2.0 -->
# Scheduled native refresh preparation — inactive

`MAESTRO_NATIVE_REFRESH_ENABLED` defaults to `false`. No repository variable,
permission, workflow dispatch or production activation is changed by this draft.
When separately enabled after review and qualification, the existing daily
`security.yml` schedule uses the existing native refresh job and excludes the legacy rolling-inventory refresh job. The distinct official-product
refresh job remains until its versioned consumer can migrate safely. Existing
explicit manual behavior and the
independent policy-drift job remain available.

The native schedule selects one successful `push` CI producer for the exact
protected current-main commit. It uses GitHub's ordinary workflow-run REST
filters (`head_sha`, branch, event and status), then checks the returned workflow,
repository IDs, source, event, exact attempt and main identity independently.
Missing, ambiguous, failed or obsolete candidates block; it never chooses an
older successful source, security decision or registry packet as a fallback.
See [GitHub workflow run API](https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-workflow).

Selection only schedules artifact reads. The unchanged native inventory verifier
must authenticate complete exact-run artifacts, original and current signatures,
all root/NAR identities, document hashes, scanner/coverage policy and executed or
retained boot proof before the closure transport is restored. For retained boot,
only the automatic route locates the original proof using the current CI result's
same-repository run/revision hint. It derives the exact attempt from the uniquely
selected immutable original CI-result artifact, rather than assuming attempt 1 or
choosing the newest attempt. These hints grant no authority: the original signed
result must independently prove direct execution, log bytes, ISO, media and
verifier bindings. Missing, substituted or ambiguous original proofs reject.
Explicit manual inputs keep their existing strict tuple contract.

The refresh downloads/restores the original authenticated closure once, verifies
its NAR identities, and invokes the existing scanner once with independently fresh
Grype/RustSec databases. Real shipped-file/npm checks remain. It emits signed fresh
health/findings only: no SBOM regeneration, closure re-export, inventory upload,
publication credential, decision record or findings acceptance. Health consumers
also permit the `schedule` event from this same protected signer workflow, with
all existing exact-run/attempt/signature, context and freshness checks unchanged.
Publication still needs a separate findings-specific human gate.

## Coverage and operational tradeoff before activation

The new scheduled target is **the exact current-main product**, with its full
existing coverage. The distinct legacy official-release refresh is deliberately
retained: replacing rolling refresh must not silently stop monitoring the shipped
official product when it differs from current main. This draft therefore removes
historical ledger selection from the rolling path, not from every consumer.

The next versioned-release consumer migration must obtain its immutable producer
identity from verified native release provenance, compare coverage with the
legacy official-product path, and remove that remaining loop after parity. Do not
retain both loops permanently for the same immutable product. Older products also
remain refreshable through explicit native run/attempt/source inputs. They cannot
publish using stale health; publication still requires fresh complete evidence
and separate human findings review.

Availability becomes explicit: if current-main CI is pending or its artifacts
have expired, the rolling native job fails closed instead of scanning an older
accepted baseline. It does not rebuild or quietly fall back. Do not enable this
route until a real signed-artifact native refresh has been qualified under
separate dispatch authorization. No monitoring threshold or findings-risk policy
is weakened by this preparation.

Focused fixtures cover exact/current selection, ambiguity and no-history
fallback, wrong repository/workflow/attempt, main races, disabled routing, original
proof discovery, malformed/changed original identities, actual shell argument
separation, fresh database behavior, NAR failure, single restore/scan, no duplicate
transport and failure cleanup. Hosted PR checks must pass; fixtures do not prove
full-size runner headroom or a live production refresh.
