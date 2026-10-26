# Maestroden migration evidence

The migration starts from protected main `d07995fec748a4e1cea456e3e8b4f2558e937573`.
The original workspace remains untouched; implementation lives in the isolated
`maestroden` jj workspace and draft PR [#170](https://github.com/closure-labs/maestro/pull/170).

Graph gating is disabled in the exported graph and the pure planner. Complete
validation remains authoritative. The existing route-plan v3/v4 and historical
qualification-state/receipt readers remain available; immutable decision and
release history is not rewritten.

Local verification uses focused fixtures and syntax checks, without full Nix
output evaluation or builds. Eighteen graph/result/verdict/diagnostic fixtures and 291 authority
fixtures pass. One duplicate workflow source-shape assertion was removed;
repository policy still enforces the exact signal-only relay. Obsolete dual-layout
fixture lookups and foreign-product path examples were also removed. No identical
authority test bodies were found. The Nix parser checked 97 files with a measured maximum child
RSS of 38,612 KiB. The standalone flake-file renderer regenerated `flake.nix`
without evaluating the appliance.

Hosted checkpoints:

| Candidate | Run | Observation |
| --- | --- | --- |
| `fdc0afff443b` | [40356049425](https://github.com/closure-labs/maestro/actions/runs/40356049425) | Found a misplaced metadata package declaration; corrected. |
| `fa404fb3c11d` | [40356585555](https://github.com/closure-labs/maestro/actions/runs/40356585555) | Found a missing native tool argument; corrected. |
| `5e3405cd0b11` | [40358015050](https://github.com/closure-labs/maestro/actions/runs/40358015050) | Found an upstream installer-module path affected by relocation; corrected. |

Hosted full-versus-graph comparison is pending. Neither executed-derivation
counts nor speedup estimates are claimed for incomplete runs. Native plan
manifests, timings, transfer manifests, boot results and the bound graph/result
manifest retain the evidence needed to compare runs on the same candidate.

The [40362371775 equivalence job](https://github.com/closure-labs/maestro/actions/runs/40362371775/job/121714048344)
passed against base `d07995fe` on immutable merge candidate `1400a1fb69a215916191f25efd4da44290507c94`.
It preserved public package/app/check names and selected effective security
settings without changing existing locked dependency identities. Raw mutation
evaluations reported:

| Mutation | Seconds | Changed registered derivations | Appliance / ISO expectation |
| --- | ---: | ---: | --- |
| Documentation | 27.896 | 10 | Both unchanged |
| CLI | 26.048 | 14 | Both changed |
| XO storage helper | 24.147 | 13 | Both changed |
| Installer implementation | 22.077 | 11 | Appliance unchanged; ISO changed |
| Packer implementation | 23.914 | 12 | Both unchanged; template output changed |
| Scan policy | 25.020 | 10 | Both unchanged; policy identity changed |

Repository-wide contracts legitimately changed with documentation; the product
outputs did not. These are evaluation timings, not execution-time savings.
The same run exposed an explicit Git-reference failure on shallow hosted
checkouts; native task/build references now declare `shallow=1`. Full build and
boot acceptance is still pending a successful subsequent run.
