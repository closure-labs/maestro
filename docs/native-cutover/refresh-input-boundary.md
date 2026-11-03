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

No active workflow, command, producer or writer calls the new API. This local
checkpoint is not the completed refresh consumer and is not yet published.
Before publishing a coherent refresh increment, implement and test one necessary
closure restore, fresh independent database scan, unchanged input/context/subject
checks, and the distinct signed fresh-health manifest linked to these original
proofs. Do not copy or re-upload original transport/SBOMs. The later consumer must
verify the new health producer/signature and freshness before current admission;
expired input identity must never be promoted directly to publication health.
Missing/expired original artifacts must fail explicitly rather than selecting a
historical authority record. Keep all active publishers and refresh jobs until
the complete path is independently reviewed and tested.
