<!-- SPDX-License-Identifier: Apache-2.0 -->
# Retained boot: download media once

In `refresh-evidence`, inventory already downloads and authenticates the original
installer media. Previously it moved the ISO into the current inventory, then
boot downloaded the original artifact again to run retained-boot verification.
The corrected #235 PR run [41917994868](https://github.com/closure-labs/maestro/actions/runs/41917994868)
spent **377 seconds** on that second download in boot job
[126898205327](https://github.com/closure-labs/maestro/actions/runs/41917994868/job/126898205327).
This is a step duration, not a measured saving or wire-byte count.

Keep both regular-file paths with hard links on the same hosted runner. There is
one ISO allocation and no extra copy; a different-filesystem or unsafe source
fails rather than falling back to another transfer. Run the existing boot-evidence
producer after the fresh scan and all successful qualification work, beside those
bytes. It still authenticates original run/state/attestations and hashes the actual
ISO. Its policy hash and original verifier sources are unchanged. Failure in the
scan, verification or upload prevents the dependent boot job from succeeding.

The dependent boot job downloads a new small `maestro-local-boot-result` artifact
from this workflow run. A leaf command checks its exact SHA-256 from the direct
qualification-job output, current producer SHA/run/attempt, graph, inventory
manifest, media input, verifier policy, ISO digest and original executed-media
identity. It preserves the exact bytes as the conventional `maestro-boot-result`.
It never changes `verified-retained` into `executed`. The later native evidence
consumer still authenticates the original executed-boot proof. Missing, substituted,
malformed, oversized or stale-attempt handoffs fail closed.

Other modes are unchanged: full media qualification executes QEMU, while `reuse`
still downloads the media once in boot because its inventory runner has no ISO.
Signing still obtains actual ISO bytes. No product roots, scan documents,
permissions, trust keys, review gates or publication policy change. There is no
new public writer, cutover activation, risk decision or background controller.

## Hosted validation and rollback

Local fixtures exercise all routing modes, the real original shell/boot verifier
with fixture attestation truth, hard-link identity, a real bounded handoff
subprocess and negative producer/content/graph/media/policy cases. Hosted CI must
verify packaged commands and all twenty audit obligations, boot and signing
contracts. The first run whose plan selects `refresh-evidence` must show:

1. One original-media download in inventory, none in boot.
2. Successful original retained-boot verification after the fresh scan, followed
   by a same-run small result download and matching final digest/producer/origin.
3. Unchanged ISO hash and complete root/document coverage, fresh database checks
   and normal final evidence acceptance.

Measure the original-media step, local verifier, handoff artifact size and total
critical path on that run. Full qualification or `reuse` runs do not establish a
refresh-mode saving. This change removes a transfer; repeated integrity hashing
and attestation checks intentionally remain. Revert this commit to restore the
previous job placement; existing artifact/result schemas stay readable.
