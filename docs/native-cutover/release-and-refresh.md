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
