<!-- SPDX-License-Identifier: Apache-2.0 -->
# Native receipt signer integration — inactive preparation

This is the one-action producer integration needed by #228–230. It adds the
existing pinned standard `actions/attest` action inside `release.yml` after ISO
staging and final-name SLSA/SPDX generation, before the native writer. Its sole
subject is the existing exact `native-release-staging.json`. It regenerates no
receipt, SBOM, ISO or closure. Existing job permissions, signer identity, human
gate, source bindings and publication serialization remain unchanged.

#229 independently requires and verifies this signature and retains the exact
small file as an immutable release asset. #228 verifies that file as scheduling
metadata; #230 then authenticates the original complete CI/inventory/boot product,
checks it against the shipped receipt, restores actual NAR bytes once and scans
with fresh databases. Neither a staging receipt nor its signature accepts risk
or authorizes a new publication.

This integration is stacked on #227's published correction `2bbb31b5`, whose
fresh hosted CI and exact-head review have passed. Merge only after that parent
converges, preserving its direct job layout and least-privilege permission ceiling.
#229 must also converge before claiming immutable receipt retention. No flag,
environment setting, gate trial or publication is activated by this code.

Fixtures enforce all three attestation subjects and their order before the writer,
the original least-privilege job envelope, required legacy key contract, strict
single release-root binding and default-off/no-fallback behavior. Real signer and
full-size token/environment qualification remain separately authorized work.
