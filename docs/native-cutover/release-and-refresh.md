<!-- SPDX-License-Identifier: Apache-2.0 -->
# Next native consumers: inactive preparation

This increment adds `release:native:stage`, an unused local asset-preparation
command. No workflow calls it; no publisher, repository setting, credential,
release environment, trust key or historical record changes. It is not a release
approval and cannot create a tag, release, cache upload or risk decision.

## Exact ISO asset staging

The command requires an explicit already-downloaded native bundle, ISO file,
source run/attempt/SHA, media run/attempt/SHA, version and new output directory.
Retained boot additionally requires the complete original executed-boot tuple.
It uses the same frozen native verifier and mandatory findings-risk boundary as
#208/#209: exact protected main/policy, complete validation, signatures, freshness,
root/NAR coverage, scanner health and boot. Accepted risk never waives these.

The supplied media producer must equal the authenticated original executed-boot
producer (or this current producer when boot executed here), and must be a
successful protected-main CI run. It must attest the exact frozen ISO bytes.
Their SHA-256 must equal both signed inventory and boot identities. A source
inventory which reused media may carry its ISO identity in the already verified
producer-signed `inventoryIsoBinding` receipt. That receipt must exactly bind this
current producer, inventory transfer hash and original boot ISO hash; missing or
substituted receipts reject. The original executed-boot media producer/signature
and actual frozen ISO bytes remain independently required. A source
version read must match protected `VERSION`; arbitrary tag/version substitution
rejects. Unsupported media/boot producer combinations reject rather than infer a
producer. In particular, a newly executed boot against media from another run
needs its separately authenticated original-media mapping before support is added.

Only after these checks does the command call the existing installer splitter
with its existing 1900 MiB part size / 2 GiB asset limit. It independently hashes
the ordered joined parts, verifies the existing ISO checksum and permits only
those parts and the authenticated system SBOM/checksum assets. The signed SPDX
and CycloneDX bytes are compressed deterministically; no SBOM is regenerated.
A final main/policy/freshness/risk-review recheck precedes local output handoff.
Failure cleans the private staging directory; an existing output is rejected.

The small `native-release-staging.json` receipt contains exact source/media
identities and per-asset sizes/hashes. It explicitly reports
`authorization:false`, `publicationReady:false`, `isoBytesVerified:true`, and
`narBytesVerified:false`. It is data for a future caller, not a capability or a
replacement provenance signature. No registry packet, reservation, history graph
or continuation controller is added.

ISO input is a no-follow regular-file snapshot, at most 32 GiB, streamed in
1 MiB blocks. The destination preflight requires three ISO sizes plus 256 MiB of
free disk, covering snapshot, splitter parts and the existing helper's possible
hard-link fallback copy. The maximum split inventory is 18 parts. These are
bounds, not hosted runner headroom measurements. Small real-subprocess fixtures
pass under a 512 MiB address-space limit. Full-size hosted ISO staging has not
been run. No Nix evaluation/build or closure restoration is needed merely to
verify and split already authenticated ISO bytes; the receipt makes no local
NAR-byte verification claim.

Before activation, independently review/merge the staged consumers and all
necessary protection changes, finish normal CI, obtain fresh exact-main signed
qualification and separately verify the workflow read-token route. The future
release workflow still must select an exact media artifact, retain its archive
identity, sign final-name provenance and the exact SPDX predicate, perform cold
installer-consumer validation, verify release-environment human protection, and
reject conflicting existing tag/assets. It must recheck drift and risk approval
before each public write. Neither this command nor its implementation approval
accepts the existing high/critical findings. A real separately reviewed risk
artifact or remediation remains necessary.

## Security refresh: retain necessary file verification

Current `decision-refresh.py` combines original signature/input authentication,
closure restoration, fresh scanners and output copying. Its input verification,
full root/NAR checks and scanner functions are reusable technical operations;
ledger selection in `decision-download.py` is a separate dependency to retire.

`security-normalize.py:component_locations` walks shipped files. Its complete
coverage pass also reads installed npm manifests and checks actual native roots.
Fresh database scanning from only current SBOM bytes cannot preserve those
checks for newly discovered component findings. Therefore the next refresh
increment must retain authenticated closure restoration and these checks.
Removing them or asserting that metadata hashes prove installed bytes would
change a security guarantee and is not part of this migration.

The smallest safe replacement is one exact CI producer's native inventories,
Cargo.lock/input hashes and original product/boot proofs, followed by one fresh
scan with its independent DB, and a separately signed fresh-health result bound
to the original product/inventory identities. An expired scan may authenticate
immutable historical inventory only; it must never pass a current health/admission
check. The consumer must distinguish the original CI proof from the later fresh
scan signer/run and still require fresh health at publication. #208 currently
expects one CI producer for both, so accepting refreshed health requires explicit
negative tests for both producer identities and the cross-proof bindings.

Avoid re-uploading the original approximately 2.85 GB transport with each refresh.
The fresh result should retain a digest-bound reference to the exact original
artifact/manifest; a future byte consumer resolves and authenticates that original
transport once. Keep its expiry/missing-artifact failures explicit. Do not invent
an alternate registry or select the newest historical decision. This follow-on is
not implemented or activated by the ISO-staging increment. Preserve all twenty
obligations, existing active refresh jobs and every historical record meanwhile.

### Distinct media and assembly producers

A retained boot receipt must pair `media_source_commit` with `media_run_id`.
The installer artifact can have been assembled and signed by a later producer;
its `artifact_source_commit` remains the inventory attestation source, not the
original boot source. Both pairs are authenticated independently. Old receipts
that mix the two producers remain invalid; this correction does not rewrite
those receipts or waive the original executed-boot proof. A fresh qualification
is required before retrying the native proof trial.

### Optional final-name attestation subject

`NATIVE_RELEASE_FINAL_ISO` (CLI `--final-iso`) optionally preserves the verified
private ISO snapshot as `maestro-v<VERSION>.iso`, alongside the selected output
directory. It must be a new sibling with exactly that basename. An existing
file/symlink, other name/parent, changed snapshot or failed handoff rejects. The
subject is a hard link to this invocation's snapshot, not the caller's mutable
download; no additional full ISO copy, download, export or SBOM generation occurs.
The existing three-ISO-plus-256-MiB free-space preflight remains sufficient. These
bounds are not a measured full-size hosted runner headroom claim.

The ISO is kept outside the public asset inventory: the existing split parts
and compressed authenticated SBOMs remain the only release payloads. The receipt
identifies the versioned subject and explicitly requires final-name attestation;
`authorization:false` and `publicationReady:false` remain unchanged. No workflow
calls this option, no attestation is created and no public writer is added.

This prepares the exact path consumed by the existing GitHub provenance/SPDX
attestation actions and `release:attestations` verifier. A future reviewed caller
must create and verify both final-name attestations, bind the exact SBOM, retain
current policy/findings review and source/freshness checks before each write,
and perform hosted-byte/cold-consumer validation. Keeping a local ISO is not
publication authority or a signature. Failed handoff removes only this
invocation's new subject link; preexisting/replaced subjects are not overwritten.
The temporary subject's lifecycle belongs to the future runner job.

The existing mandatory findings gate also remains unchanged in this local helper:
blocking unaccepted findings produce no subject or assets. The new option does
not create an exception or accept current findings. Full-size hosted handoff and
final-name signing remain unvalidated until a separately reviewed eligible caller
exists; tiny subprocess fixtures and theoretical disk bounds do not establish
production runner headroom.

### Explicit immutable product and current policy revisions: inactive proposal

An optional `--policy-revision` (`NATIVE_POLICY_REVISION` for the native consumer
and release wrappers) separates two identities. `--revision` remains the exact
qualified product source, run and attempt. The explicit policy revision must be
the current protected main commit, and the product source must be its GitHub-
verified ancestor. Omitting the option retains the original exact-current-main
behavior; no product or current-policy revision is chosen implicitly.

This permits a separately reviewed risk artifact merged after qualification to
refer to the exact older artifact. It avoids forcing a rebuild or new SBOM just
because the findings-review commit advances main. Original source/run/attempt,
signatures, root/NAR coverage, security context and original boot proofs stay
bound to the product. Current effective policy, the dedicated findings-risk PR,
CODEOWNERS and live reviewer access are read at the policy revision. Changed
findings/product/context or incompatible policy still reject. Both revisions
remain frozen, and main/policy/freshness/access are rechecked before writes;
the writer must run in the exact current policy workflow context.

**Admission delta for later review:** an explicit qualified ancestor product may
be promoted instead of requiring the product source to equal the latest main.
This is immutable-artifact promotion, not permission to choose a historical
leaf, skip signatures, reuse expired health or carry over previous acceptance.
No existing workflow passes the new option and no writer is activated. The
maximum-30-day human risk decision and access-loss/reapproval requirement remain;
current permission checks still do not establish loss-and-restoration continuity,
which continues to block activation.

Fresh health has its own exact run, attempt and signer revision. That producer
must be a successful protected-main security workflow and an ancestor of the
explicit current policy revision. A version 2 manifest separates its scanner/
policy source from the original product source; historical version 1 manifests
retain their strict same-source producer shape. The reader authenticates original
CI/boot proofs and fresh health independently and rechecks current policy, scope,
database age and finding bytes. Expired original evidence is inventory only until
fresh health is authenticated. Changed/new findings still need a new decision.

The refresh restores and verifies the original NARs once for shipped-file/npm
coverage, generates no new SBOM, and retains only fresh health plus authenticated
references to original input/transport. It does not re-export the old closure.
Current policy can advance without rebuilding the exact immutable product or
reissuing still-valid fresh observations. A later product/configuration commit is
not silently incorporated into the explicitly selected older artifact: that is
part of the admission delta. Incompatible policy or expired health still reject.

This is not a compatibility waiver for old official releases lacking complete
original native proof. The full native versioned-release writer and cold public
consumer still require reviewed wiring and validation; no settings or writers
are activated here.


### Inactive native versioned writer

`release:native:publish` is a declared task with no workflow caller. It uses the
native publisher's mandatory findings verdict and requires
`MAESTRO_NATIVE_RELEASE_ENABLED=true` in a protected-main manual workflow at the
explicit current policy revision. The flag defaults false; this source addition
changes no repository variable, environment, credential, permission or writer.

Inputs are the exact verified original/fresh-health evidence selection plus
`NATIVE_RELEASE_DIRECTORY` and `NATIVE_RELEASE_ISO`. The staging receipt is only
data: the writer independently checks the product source/run/attempt, VERSION,
current policy, exact allowed assets, part sequence, joined ISO digest against
authenticated boot proof, checksums, and expanded SPDX/CycloneDX bytes against
the signed original inventory. It never regenerates a bill of materials or
re-exports a closure. A verified inventory without fresh health still rejects.

The existing `release:attestations` verifier must successfully verify both SLSA
provenance and the entire SPDX predicate for the exact final ISO filename,
digest and protected-main release-workflow source. Metadata or a staging receipt
does not substitute for ISO-byte or cryptographic verification. Private asset
snapshots prevent source-path changes between verification and upload. The
versioned ISO is linked for verification, never uploaded as an extra full asset;
existing split parts/SBOM/checksum contracts remain unchanged.

After these checks, the existing `publication-assets.reconcile` operations
reserve the exact product tag, create/resume a draft, reject conflicting or
unexpected assets, upload only missing verified bytes, perform complete hosted
readback and publish. Its authorization callback is native main/policy/evidence
freshness plus the live dedicated findings-risk review. No historical graph,
OCI packet, journal branch, reconciliation dispatcher or live custom admin
approval is invoked. An uncertain upload is resolved by the existing exact
remote inventory/digest readback before any new upload; no automatic retry is
added. Nonzero attestation/upload/readback failures propagate.

A private copy adds at most the 32 GiB ISO-part bound plus 256 MiB compressed
metadata, with an additional 256 MiB free-space reserve checked before copying.
It adds no ISO/closure network handoff, but it does add local disk I/O. Only tiny
real-subprocess fixtures have run: production peak disk/RSS, full-size SPDX
attestation memory, hosted readback and idempotent interrupted upload still need
an explicit nonpublishing hosted trial. These fixtures do not establish runner
headroom. The standard verifier retains its current timeout/resource behavior;
this change does not silently loosen it.

Activation remains blocked on independent exact-head review, reliable
reviewer-loss/reapproval continuity, sole-maintainer-compatible protections and
the actual fresh cryptographic trial after the boot-origin correction. Existing
current-access checks cannot detect an unobserved removal followed by restoration.
GitHub's documented audit API requires organization Administration read and
GitHub Enterprise Cloud availability; neither that permission nor capability is
established by the current repository-scoped token. No grant, new credential or
audit controller is added here. A history backend must demonstrate complete
effective-access transitions and reject missing/truncated/denied evidence;
current permission or a merely empty audit response is not proof of continuity.

The remaining caller migration should preserve the existing release producer's
read/provenance role and publisher's contents-write role. Do not consolidate
those credentials into one job merely to avoid a native artifact handoff. A
reviewed exact producer/artifact handoff, final-name signing, cold public reader
and disabled legacy writers are still prerequisites; this helper alone does not
complete or activate the cutover. No vulnerability findings are accepted.

Sources: [GitHub organization audit API](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization),
[audit API availability](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#using-the-audit-log-api).


### Caller preparation for the explicit source/policy split

The existing disabled native cache writer and read-only cache probe pass their
explicit product `native_revision` separately from protected workflow
`github.sha` as the policy revision. Their enabling conditions and permissions
are unchanged. The manually requested read/sign-only native refresh accepts the
same explicit product revision; its empty default keeps current-main product
selection. Its signer/policy source remains the exact workflow revision, and the
verifier rejects main drift or a nonancestor product. No schedule starts native
mode, no workflow calls the new versioned writer, and no live setting is enabled.
This allows later policy/findings-review commits and fresh scans without
rebuilding or regenerating the bill of materials for the immutable product.
