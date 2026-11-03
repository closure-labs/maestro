<!-- SPDX-License-Identifier: Apache-2.0 -->
# Local refresh-input preparation; not activated

`verified_inventory` is a purpose-limited private API for a future native rescan.
It authenticates the original exact-main CI producer, complete validation, all
root/NAR/document bindings, signatures and original executed/retained boot proof.
It additionally freezes and authenticates the original input checksum file and
Cargo.lock against the signed native report, including both CycloneDX inputs.
Historical scanner health/DB must have been valid at that original scan time;
future, malformed or originally unhealthy inputs reject.

The original scan may now be expired only because this API supplies immutable
input identity, not current health. Its receipt explicitly reports
`currentHealthVerified:false`, `authorization:false`, `publicationReady:false`
and no NAR/ISO-byte verification or risk evaluation. The publisher rejects this
purpose even when its timestamps happen to remain fresh. The existing current
health CLI remains strict and has no option to select historical-input mode.

No automatic workflow or writer calls the new API. This local checkpoint is not
the completed refresh migration and is not yet published or dispatched.

The unused `native-refresh.py` producer now performs one necessary original
transport download/closure restore, exact root/NAR readback, and one invocation
of the existing scanner with its fresh temporary Grype and RustSec databases.
It retains shipped-file/npm verification against those restored NARs. It checks
unchanged original input hashes, subjects and security context, originally bound
scope policy, current main before/after phases, and a scan timestamp from this
invocation. Failure removes the partial output. Scanner timeout stays 3600s;
Nix identity output is file-limited to 16 MiB; completed individual report files
are checked against 64 MiB and aggregate reports against 256 MiB before handoff.
The scanner retains its existing temporary DB filesystem contract: a global
report-size ulimit would wrongly truncate larger legitimate database files.
These are bounds, not measured
hosted runner headroom; no scanner/build has been run locally.

Its small `native-health.json` links the exact original metadata/document hashes,
including original executed-boot proof when retained, original transport
descriptor, and fresh result hash to distinct original/fresh producer identities.
It grants no authorization or publication readiness. It does not copy or re-upload
original transport/SBOMs.

The unused `native-health.py` context authenticates the completed exact-main
`security.yml` run and its exact manifest attestation with fixed source/signer
SHA, protected ref and hosted-runner restriction. It checks original proof and
transport hashes, strict fresh result/input/finding/policy bindings, unchanged
root/context coverage and current DB/scan freshness. The original signed scan is
never reissued with new timestamps: its product/boot/inventory context stays
separate from the new health manifest and policy files. The publisher still
applies its mandatory findings-risk gate, including high/critical/unknown when
source metadata says report mode. The context and frozen new policy directory
exist only for that invocation. `stage_health` downloads one uniquely named,
exact-run artifact with the existing ZIP/digest/size/member bounds.

The `ci:native:refresh` command and explicit `native_refresh` manual option on
the protected-main Security maintenance workflow stage one specified CI run and
attempt, verify its original proof, restore once and scan once, attest the new
health manifest and upload only the fresh scanner reports, including raw Grype,
RustSec and DB diagnostics. The consumer selects its seven bound input files.
The producer rejects unexpected file names, directories or resource overflow;
original inventories and transport parts are absent from that output. They do not create a
branch, PR, decision, release or cache write. No scheduled route changes. When
that manual option is selected, both old rescan jobs skip so the trial does not
repeat their work. The current standard-read-only policy drift job remains.

Native publication/probe accept optional exact health-run/attempt inputs; they
keep their existing disabled activation flag and current mandatory risk review
gate. Supplying a refresh directory without its exact producer, missing or
mismatched original evidence, invalid fresh signature or expired health rejects.
The original CI source/transport/boot references remain independently verified.

Local real-CLI fixtures exercise both producer verifications and clear/blocked
policy paths; fake transport/scanner boundaries make no live network or NAR
claim. They prove that high/critical/unknown rows still block before Nix/Cachix
writes and that invalid original/fresh proof, changed scope, resource overflow,
timeouts and failed scanners reject. Read-only isolated fixtures cover the CLI
and workflow conditions. The Go YAML reader needs its normal virtual-address
reservation; that small fixture measured 25,152 KiB child RSS, not a 512 MiB
address-space cap. Python evidence fixtures retain their 512 MiB limit.
The generated original-plus-fresh report CLI fixture exceeds both measured
production document sizes and passed with 194,436 KiB peak parent RSS and
194,436 KiB peak child RSS (a conservative summed upper bound below 512 MiB).
It contains generated data and fake verification endpoints, not production
evidence or a live database/NAR/ISO trial.

Hosted packaging/normal CI and a later independently reviewed protected-main
signing/scan trial remain before claiming hosted parity or activating any
consumer. The current path covers exact-current-main CI inputs only; refreshing an older official release
under a newer scanner/source revision is not implemented. Its legacy consumer
must remain until that separately tested path exists. Both consumers must
verify the new health producer/signature and freshness before current admission;
expired input identity must never be promoted directly to publication health.
Missing/expired original artifacts must fail explicitly rather than selecting a
historical authority record. Keep all active publishers and refresh jobs until
the complete path is independently reviewed and tested.

## Same-coverage hosted trial before cutover

Use one fresh successful exact-main qualification and its explicit original
executed-boot tuple. Record all artifact IDs/archive digests, root/NAR and ten
inventory-document identities, source policy, original/fresh run attempts and
signer identities. Run the manual refresh only after independent review/merge.
Verify its new manifest signature, fresh DB/RustSec/scanner receipts and full
subject/context equality. Compare normalized findings against the existing scan
on those same immutable inputs and database versions; different database versions
must be reported rather than called parity. Expect the current unaccepted
blocking findings to deny publication.

Measure hosted phase durations, disk and process peaks, original transport and
fresh artifact stored sizes. One original transport download/restore and one
scan remain necessary; inventory generation, copying/re-uploading old SBOMs and
copying/re-uploading the roughly 2.85 GB transport are absent. These are work-count
changes; static tests do not establish time, bandwidth or disk savings. Preserve
old scheduled/official-release refresh until its native consumer has equivalent
technical and findings-review coverage. No historical authority record is used
as the trial input selector or changed by the trial.
