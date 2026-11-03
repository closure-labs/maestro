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

No active workflow, command or writer calls the new API. This local checkpoint
is not the completed refresh consumer and is not yet published.

The unused `native-refresh.py` producer now performs one necessary original
transport download/closure restore, exact root/NAR readback, and one invocation
of the existing scanner with its fresh temporary Grype and RustSec databases.
It retains shipped-file/npm verification against those restored NARs. It checks
unchanged original input hashes, subjects and security context, originally bound
scope policy, current main before/after phases, and a scan timestamp from this
invocation. Failure removes the partial output. Scanner timeout stays 3600s;
Nix identity output is file-limited to 16 MiB; individual scanner files are capped
at 64 MiB and aggregate report files at 256 MiB. These are bounds, not measured
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

Signing/workflow/task wiring and CLI selection of this independently verified
health context remain to implement and test before publishing a coherent
refresh increment. No wrapper currently calls this new path. It currently
covers exact-current-main CI inputs only; refreshing an older official release
under a newer scanner/source revision is not implemented. Its legacy consumer
must remain until that separately tested path exists. Both consumers must
verify the new health producer/signature and freshness before current admission;
expired input identity must never be promoted directly to publication health.
Missing/expired original artifacts must fail explicitly rather than selecting a
historical authority record. Keep all active publishers and refresh jobs until
the complete path is independently reviewed and tested.
