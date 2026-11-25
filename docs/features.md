# Feature navigation

Maestro has one appliance, `nixosConfigurations.maestro`, composed explicitly by
`modules/features/appliance/composition.nix`. Flake-parts owns outputs; Den owns
NixOS and Home Manager aspect values. One import-tree discovers ordinary module
files. `_source/`, `_tests/` and `_lib/` are private and never auto-imported.

| Where to change… | Owner |
| --- | --- |
| Appliance composition or host wiring | `modules/features/appliance/` |
| Durable operator policy | `host/settings.nix` |
| Disks and filesystems | `host/hardware-configuration.nix` |
| Generated console overrides | `host/menu.nix` |
| Boot, networkd, DBus switching or Nix GC | `modules/features/platform/` |
| Operator options, SSH or management networks | `modules/features/operator/account.nix`, `access.nix` |
| CLI behavior | `modules/features/operator/cli/_source/` |
| Ratatui frontend or console backend | `modules/features/operator/menu/_source/` |
| XO service, storage privilege or TLS | `modules/features/xo/` |
| Bounded file restore | `modules/features/xo/file-restore/` |
| ISO or installation behavior | `modules/features/installer/` |
| Guest integration or native Packer template | `modules/features/xcp-ng/` |
| Native development tools and tasks | `modules/features/development/` |
| CI graph and target registration schema | `modules/ci/graph/` and each owner's `ci.nix` |
| Repository-wide contracts | `modules/ci/checks/` |
| Native inventory and scanning | `modules/ci/inventory/`, `modules/ci/security/` |
| Live decision authority and historical receipt readers | `modules/ci/authority/` |
| Publication contracts | `modules/release/publication/` |
| Inputs, follows, caches and generation | `modules/flake/` |

[Generated output ownership](feature-outputs.md) covers every existing audit,
media, evidence and publication target. `lib.ciPlans.x86_64-linux` is generated
from typed feature registrations. The committed graph plan data preserves
existing native readers and is checked against those registrations. Regenerate
plan data with `devenv tasks run ci:graph:write-plans`. Regenerate
`flake.nix` with `nix run .#write-flake`; `check-flake-file` verifies it in CI.
Inspect evaluated graph JSON with:

```bash
nix eval --json .#lib.ciGraph.x86_64-linux
nix run .#maestro-ci-graph -- candidate.json
nix run .#maestro-ci-graph -- candidate.json --ownership
```

CI evaluates immutable candidate/base source archives for PR, merge queue and
main events. Unknown graph versions, absent base graphs and unmapped inputs
require complete validation. Ordinary CI resolves evaluated qualification identities
even for documentation-only changes; changed-path hints cannot authorize a skip.
The explicit validation-only dispatch remains available. Target equality describes potential deterministic
cache reuse; authenticated producer bindings, verifier/policy identity, current
databases and live review authority remain separate obligations.

The current [CI maintainer guide](ci/README.md) describes the seven-job pipeline,
manual controls and recovery. Complete audit and qualification execute in
parallel after planning. Appliance and installer builds, inventory, fresh scan
and boot verification share one runner and Nix store. Signing remains separate
and protected-main only. **Required CI verdict** retains its existing name and
App binding, alongside CodeQL and review requirements.

All twenty audit obligations remain required. The audit binds its completed
manifest on the same runner; there is no raw-audit transfer or extra join job.
Native version 2 results bind that audit directly. Historical version 1 readers
retain their comparison-proof requirements. The migration equivalence job,
comparison job and decision-only retained shortcut are retired; historical
measurements remain in [migration evidence](maestroden-evidence.md).

Same-attempt version 2 manifests bind graph digest, derivations, output paths,
NAR hashes, native index bytes and producer/run/attempt. Appliance and installer
manifests use local verification without closure export/import. Inventory binds
the SBOMs and exact ISO bytes. The final protected-main report retains the
existing bounded distribution transport for publication and installer consumers;
its readers continue verifying exact bytes and never silently build replacements.
Boot results distinguish `executed` from `verified-retained`. Inventory covers
installer boot content and distributed tools as well as the appliance. Scan
freshness and live publication authority retain their native verifiers.

The bound final native route owns step selection. Graph mode remains part of
signed evidence compatibility, rather than a second set of workflow job guards.
Unknown comparison inputs or legacy unbound routes require complete
qualification. Native routing regenerates both route and producer state, rather
than editing a mode over an older pointer. Explicit validation-only dispatch
remains available; force-build controls override it. Ordinary PRs cannot select
validation-only operation. A historical decision descriptor cannot waive any
qualification step.

The appliance phase realizes appliance and standalone outputs. The installer
phase realizes ISO and copied/generated content origins. Inventory uses these
verified local roots without restoring closures or rebuilding product content.
Copied-origin metadata preserves every Nix source context rather than claiming
an arbitrary first context is the sole producing derivation.

Qualification fingerprints bind exact appliance/ISO and inventory-root producing
derivations as well as their existing output paths and verifier identities.
Changing a recipe with equal output paths cannot reuse an older qualification.
The additive identity fields preserve historical state/receipt formats; older
fingerprints remain readable but do not satisfy the new identity contract.

Deterministic audit derivations explicitly permit substitution from the configured
trusted Nix caches. `runCommandLocal` otherwise disables substitution by default;
its local-build preference is retained for cache misses. Every audit obligation
still requires its exact evaluated derivation. Graph targets expose effective
`cachePolicy.allowSubstitutes` and `cachePolicy.preferLocalBuild` flags, and current
exports reject disabled substitution on deterministic validation targets. Older
schema-one graphs without those inspection fields remain readable.

The deterministic runtime-security VM check can reuse a matching approved Nix
result. The installer media boot obligation still requires executed or
authenticated retained boot evidence bound to exact ISO and verifier identities.
Current security databases, effective policy and live human authority remain
per-run checks. Diagnostics identify substituted outputs without counting them as
newly executed tests. Cache availability is observed in hosted runs; no timing
improvement is assumed.

### Interrupted decision packet inspection

After separate human review and merge, the manual **Inspect interrupted decision
packet** workflow may inspect the one request committed in
`modules/ci/authority/_source/decisions/packet-inspection-request.json`. Confirm
request hash `f342d0b3f3666219d87a6ad9bc27f529929c322247c4e290b83710065bdfbf51`.
Its native `ci:decision:packet-inspect` task binds reconciliation run
41267014336 attempt 1, qualified producer 41262202226 attempt 1, the retained
report artifact, and every one of the reconstructed 22 packet members.

The workflow uses only its repository GitHub token with contents/actions/package
read permissions, never a Decider write token or private key. It authenticates
the original request in retained exact-job logs, resolves the derived packet tag
to an immutable digest, and reuses the bounded manifest/descriptor verifier.
It downloads only the descriptor blob, not closure payloads. The seven-day,
bounded diagnostic receipt records `authorization: false`; it cannot create a
security decision, branch or PR, upload a packet, approve risks, queue or merge.
Missing logs, expired/mismatched artifact bindings, denied/404 responses and
transport failures remain unresolved. A missing response never proves absence.
This historical inspection grants no current freshness, authority or recovery
permission; a later recovery still needs fresh qualification, complete graph,
policy, evidence and live human authority checks. Other targets require a new
separately reviewed request and implementation change, not arbitrary workflow
inputs. Do not redispatch ordinary recovery to inspect an uncertain write.
