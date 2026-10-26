# Maestroden migration evidence

The migration starts from protected main `d07995fec748a4e1cea456e3e8b4f2558e937573`.
The original workspace remains untouched; implementation lives in the isolated
`maestroden` jj workspace and draft PR [#171](https://github.com/closure-labs/maestro/pull/171), authored by
`cl-decider[bot]`. It supersedes the Dale-authored #170 so Dale can review.

Graph gating is disabled in the exported graph and the pure planner. Complete
validation remains authoritative. The existing route-plan v3/v4 and historical
qualification-state/receipt readers remain available; immutable decision and
release history is not rewritten.

Local verification uses focused fixtures and syntax checks, without full Nix
output evaluation or builds. Eighteen graph/result/verdict/diagnostic fixtures and 291 authority
fixtures pass. One duplicate workflow source-shape assertion was removed;
repository policy still enforces the exact signal-only relay. Obsolete dual-layout
fixture lookups and foreign-product path examples were also removed. No identical
authority test bodies were found. The Nix parser checked 145 files with a measured maximum child
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

The [40368324646 checkpoint](https://github.com/closure-labs/maestro/actions/runs/40368324646)
passed graph planning, all CodeQL languages, the appliance/standalone build and
hosted migration equivalence on immutable merge candidate
`de5c318cea4172e4bd1c515280c068e4862a41de`. The graph contains 31 targets and
13 appliance, one ISO and 60 inventory transport roots. Planning took 16 seconds
inside the native graph command. Complete validation was selected because the
base has no graph.

| Mutation | Seconds | Changed registered derivations |
| --- | ---: | ---: |
| Documentation | 28.966 | 10 |
| CLI | 26.571 | 14 |
| XO storage helper | 26.573 | 13 |
| Installer implementation | 30.847 | 11 |
| Packer implementation | 29.001 | 12 |
| Scan policy | 27.615 | 10 |

The complete audit accounted for all 20 obligations: 18 passed, including
runtime-security, operator, release, security and Packer fixtures. Two migration
plumbing checks failed: the isolated graph fixture derivation omitted its Bash,
coreutils and jq command dependencies, and the formatting fallback used a path
that did not match its contract. Both are corrected in the next checkpoint.
Raw Nix events remain retained; console output now renders messages and build
logs without copying high-volume progress events into the job log. Full
installer/boot/scan acceptance remains pending.

The retained 291 authority fixtures passed locally in 1.99 seconds with a
measured peak resident set of 224,420 KiB. Graph fixtures also pass with a
512 MiB virtual-address limit. Tools implemented in Go reserve more virtual
address space than their resident memory, so their memory observations use
measured RSS rather than that address-space limit.

The [40372043017 corrected checkpoint](https://github.com/closure-labs/maestro/actions/runs/40372043017)
passed graph planning, hosted equivalence, all 20 audit targets (zero failures),
the appliance/standalone build and the installer ISO build. Native validation
took 533 seconds. The ISO job downloaded the 2.85 GB appliance transport in
506 seconds, then restored/verified that closure and realized the exact ISO in
302 seconds. Excluding separately retained raw diagnostics reduced the closure
artifact from 4.92 GB to 2.85 GB. This does not establish an execution speedup.
The earlier successful appliance trace observed 105 build derivations and 1,401
substitution paths; those observations do not count substituted checks as newly
executed tests.

Hosted graph snapshots before and after the CI plumbing corrections have equal
appliance, ISO, CLI and menu derivation identities. The final checkpoint also
binds retained media to the compiled boot command and boot verifier derivations,
so changes to their transitive packaged dependencies invalidate reuse as well
as changes to the explicit verifier/policy source hashes. Full end-to-end
verification of that final checkpoint is pending. Graph gating remains disabled;
there is no same-candidate full-versus-graph scheduling comparison yet, and the
measured transport cost must be included in that comparison.

The [40377085629 full checkpoint](https://github.com/closure-labs/maestro/actions/runs/40377085629)
passed all planned jobs and **Required CI verdict** on immutable merge candidate
`db6178114f6264b36d80bc585170eff35c32a826`: all 20 audit obligations, effective
policy/public-interface equivalence, appliance/standalone and ISO builds,
inventory, an executed QEMU boot, current-database scanning and complete bound
release evidence. CodeQL passed independently. The summary recorded 247 distinct
build-derivation activities, 1,806 substitution paths and zero incomplete/failed
traces. Those observations do not count reused derivations as newly run tests.

| Job | Seconds |
| --- | ---: |
| Plan CI | 314 |
| Repository checks | 637 |
| Equivalence and mutation checks | 414 |
| Build appliance | 526 |
| Build installer ISO | 524 |
| Generate release inventory | 1054 |
| Test installer boot | 195 |
| Scan release outputs | 494 |
| Verify release evidence | 179 |
| Required CI verdict | 164 |

Concurrent durations are not additive. This full run is the completed migration
baseline; it was not a full-versus-selective scheduling experiment.

The continuation adds a separate, same-attempt audit comparison: first bind the
complete audit manifest and timings, then re-evaluate the identical candidate and
realize all 20 validation derivations directly from its graph on a separate
runner. `maestro-ci-comparison` retains raw traces, full/graph timings and exact
output-identity comparisons; `maestro-ci-comparison-binding` contains the small
producer-bound receipt used by release evidence and the required verdict.
Hosted acceptance of this new comparison is pending. It does not authorize
selective media/inventory/boot reuse, so graph gating remains disabled.

Continuation fixtures: 24 graph/result/verdict/comparison cases pass within a
512 MiB address-space limit; all 291 authority cases pass. ShellCheck, modified
Nix syntax and workflow syntax checks pass locally without full Nix evaluation.

The source-ownership continuation removes duplicate hash-update and CI-runtime
fixture executions from the operator suite and moves the repository-wide
identity scan into `repository-policy`. Shell parsing remains covered by
`shell-lint`. The operator suite passes against an explicit source subset that
excludes documentation, unrelated release logic and authority fixtures. Its
real Git-staging regression exposed obsolete root pathspecs left after source
relocation; the CLI now stages the current `host/` and `modules/` layout without
requiring removed implementation directories.
