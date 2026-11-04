<!-- SPDX-License-Identifier: Apache-2.0 -->
# Explicit official-release refresh route — inactive

Stacked on #228's private signed-receipt locator, this adds an opt-in route to the
existing `security.yml` manual native refresh. It changes no schedule, activation
variable, permission grant, environment or legacy default. It is not a dispatch
request and performs no actual findings acceptance or publication.

After independent review and prerequisite producer integration, a separately
authorized manual invocation can set `native_refresh=true`, an exact
`native_official_tag` and `native_official_publication_revision`. Leave the
original-run and boot fields empty in this mode. The signer revision is explicit;
it is not guessed from an arbitrary historical decision or newest approval.
Conflicting official/current/manual identities reject. Entering official fields
also suppresses the legacy jobs, even when `native_refresh` is accidentally false:
there is no silent historical-ledger fallback.

The existing native command downloads at most 1 MiB of the one fixed staging
receipt asset using its numeric GitHub asset ID (90-second transfer deadline).
It checks transfer length/digest, then authenticates the exact existing release
signer, subject, stable tag, asset, source/signer ancestry and main/tag races.
No ISO, SBOM or closure is downloaded merely to locate the product.

The verified tuple enters the unchanged complete native inventory verifier.
Retained boot locates its original proof from immutable CI hints, then requires
the signed original directly executed result/log and all media/verifier bindings.
The authenticated inventory's producer, original media tuple and ISO digest must
match the published receipt **before** transport restore or scanning. Receipt
signature verification cannot waive any CI, coverage, provenance or boot failure.

Only then does the existing native refresh download/restore the closure once,
check actual NAR identities, and scan the original inventories once using fresh
vulnerability databases and real shipped-file/npm checks. It emits the existing
signed health artifact only. There is no SBOM regeneration, closure export,
product re-upload, new scanner, duplicate realization or new workflow controller.
Existing 45-minute job/40-minute command budgets remain unchanged; full-size
hosted headroom and runtime are still unproven for this route.

## Dependencies and retirement boundary

- #228 supplies the private locator; this PR is stacked on its branch.
- #229 prepares signed receipt retention. #227's pending correction and a later
  standard receipt-attestation action inside its reviewed signer job must converge
  before a usable official native receipt can exist. Existing releases without
  that proof reject; none are rewritten or grandfathered here.
- Qualify this explicit route against the actual shipped native product, including
  original boot, unchanged full root/NAR/document/upstream XO scope and fresh scan.
  Missing signatures, changed ISO/media, failed NAR restore, unhealthy scanners,
  stale databases and main/policy races must prevent fresh health.
- The distinct scheduled `release_candidates` job remains unchanged until parity
  is proven. Its automatic target selection and deduplication with rolling refresh
  are a subsequent small integration: deduplicate only authenticated identical
  products, retaining separate scans for genuinely different inventories.
- Only after that cutover/reference audit may the old official refresh and
  ledger/event/recovery callers retire. Preserve historical records.

Fresh health is not an acceptance of its findings and cannot authorize a cache or
release write. Every publication still needs its own exact findings-specific
human approval and current evidence/access checks. All live security settings and
the GitHub Free review tradeoffs remain unchanged.
