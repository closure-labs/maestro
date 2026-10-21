# Release recovery brief

Target: closure-labs/maestro and closure-labs/xo-nixpkg, isolated /tmp checkouts
based on live main 020ac05c and cd6fc794 respectively. Existing workspaces stay
untouched.

Goal: fix qualification and publication; simplify and optimize CI/CD, scans and
caching where the mechanism's cost exceeds its purpose.

Done when: each previously failing check has a named cause and passing evidence
on the proposed commit; all repository contracts pass; independent QA and
security reviews pass; after required release approvals, hosted qualification,
release and recovery operate on the exact reviewed product bytes.

Repro: xo-nixpkg qualification run 39496476933 fails with `Reuse run must identify
one protected-base PR`; xo-nixpkg publisher run 39501579918 fails its authority
main-ref read with HTTP 403; Maestro publishers 39501131681 and 39496462012 fail
the equivalent authority main-ref read.

Gates: native repository audits, exact-commit hosted checks, independent QA and
security review, skill gate:ship and existing protected-main/human product
approval. A local fixture is not proof of hosted publication.

Invariants: no credential in Nix evaluation/store, no test/check bypass, no
unverified product distribution, complete healthy fresh scans, exact output
and provenance checks, no monolithic automation dispatcher. Existing appliance
and XO policy scope remains unchanged.

Assumptions: retain the existing security contract while considering simpler
implementations; substantive trust-boundary redesign is a concrete architecture
decision, not an implicit consequence of a performance optimization.
