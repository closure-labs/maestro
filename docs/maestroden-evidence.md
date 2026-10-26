# Maestroden migration evidence

The migration starts from protected main `d07995fec748a4e1cea456e3e8b4f2558e937573`.
The original workspace remains untouched; implementation lives in the isolated
`maestroden` jj workspace and draft PR [#170](https://github.com/closure-labs/maestro/pull/170).

Graph gating is disabled in the exported graph and the pure planner. Complete
validation remains authoritative. The existing route-plan v3/v4 and historical
qualification-state/receipt readers remain available; immutable decision and
release history is not rewritten.

Local verification uses focused fixtures and syntax checks, without full Nix
output evaluation or builds. Ten graph/result fixtures and 292 authority
fixtures pass. The Nix parser checked 97 files with a measured maximum child
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
