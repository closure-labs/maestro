<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development

## Current CI and publication contracts

Publication metadata download, destination inspection, cache publication and
journaling use Devenv’s native `--show-output` task option. Their public
verification results and the cache’s no-transfer fast-path message remain in
hosted logs even when tasks succeed; authorization and receipts still come from
the existing native commands.

The current authority, candidate transport, release approval, recovery, and
coordinated activation procedure is documented in [CI and security](ci-security.md).
Publication commands require authenticated `DECISION_SCANS` and
`DECISION_PRODUCT`; a validation build manifest alone no longer authorizes cache
writes. The older orchestration examples below retain their diagnostic context.


The committed devenv module is the development-toolchain and task boundary.
Enter it interactively with:

```bash
devenv shell
```

The flake imports the same package definition, so the compatible Nix interface
provides the toolchain directly:

```bash
nix develop --accept-flake-config
```

For one-off commands, keep the boundary explicit:

```bash
devenv shell -- cargo --version
devenv shell -- packer version
```

The default shell provides the repository's pinned Rust compiler and tooling,
Nix language tools, Packer, GitHub CLI, Secretspec, and workflow and shell
linters.

## Validate a change

Run the complete flake-packaged CI contract before publishing:

```bash
nix run --accept-flake-config .#maestro-ci-repository-audit -- --no-write-lock-file
```

Use the leaf packages directly for individual automation operations:

```bash
EVENT_NAME=workflow_dispatch VALIDATE_ONLY=true \
  nix run --accept-flake-config .#maestro-ci-route
nix run --accept-flake-config .#maestro-ci-classify-paths < changed-paths.txt
nix run --accept-flake-config .#maestro-ci-qualification-inputs
nix eval --json .#lib.ciPlans.x86_64-linux.validation
nix run --accept-flake-config .#run-ci-plan -- \
  --plan lib.ciPlans.x86_64-linux.validation
```

GitHub workflow command bodies invoke declared tasks through the thin pinned
`devenv` flake app. Each task resolves an explicit `maestro-ci-*` leaf package;
there is no umbrella automation dispatcher. Workflow YAML retains only GitHub
runner, permission, environment, artifact, and attestation boundaries. Product
operations use `maestroctl`; delivery automation uses Nix-packaged leaf programs.
Automation programs and security-sensitive XO helpers remain native shell
sources, while Nix provides their runtime dependencies and executable app
boundaries.

Workflow policy allowlists Actions only for GitHub-platform boundaries:
checkout, Determinate Nix bootstrap, artifact upload/download, attestations,
and FlakeHub's OIDC publication. Linters, formatters, compilers, Cachix, and
repository orchestration are ordinary pinned executables supplied by Nix, so
the same commands run locally and on hosted runners.

Hosted leaf tasks use Devenv's `--mode single` so they execute only the named
boundary. The aggregate `ci:repository-audit` task remains dependency-aware
and has no command of its own after its declared flake and formatting checks
finish.

The `runtime-security` check boots the appliance and storage peer to verify
network, SSH, TLS, service privileges, crypto and NFS/CIFS/VHD boundaries.
It does not run the nested libguestfs file restore VM acceptance scripts;
file restore unit fixtures still run through `security-fixtures`.

Every hosted Nix job uses the shared Determinate setup. It records the installed
CLI path and preserves it through packaged commands, including `nix-store`.
The setup's export helper accepts only Determinate Nix store paths and
positive numeric budgets before writing runner environment/path files;
the credential access reason is a fixed literal. Injection fixtures verify
invalid or multiline values leave those files unchanged.
The setup writes supported overrides to `nix.custom.conf`, derives jobs/cores
from detected CPU and RAM, reserves 8 GiB for VM tests and runner processes,
and exports the same budget to devenv. Runners with at most 8 GiB reserve
2 GiB and execute one build at a time, with a one-core minimum on very small
runners. A four-core, 16 GiB runner gets two jobs with two cores each;
a two-core, 7 GiB runner gets one job with two cores. Workflow fixtures prevent
new Nix jobs from bypassing this setup.

Hosted commands resolve explicit SecretSpec profiles through the env provider
at runtime, with an explicit access reason. Devenv disables implicit project
secret resolution; local keyring setup is opt-in below. Credential-free
audits and dummy-token runtime injection are checked independently. Devenv's
pinned native evaluator is separate from the hosted Determinate CLI and may
warn about unsupported Determinate experimental flags. The pinned sbomnix
package deliberately retains Nix 2.31 for its older derivation-JSON parser;
this scanner compatibility tool is distinct from the audit/build CLI.

XO and its supply evidence are downloaded from the signed public
`xen-orchestra-ce.cachix.org` cache at the exact locked output paths. A plan
runner's "Building" target label can also mean substituting an existing
output; the Nix download/build logs establish which occurred. Maestro publishes
its own runtime closure to Cachix after successful protected-main qualification
and signing. Failed PR runs do not publish new Maestro build outputs, so custom
QEMU/appliance builds can repeat before the first successful main publication.
Installer/evidence reuse separately requires a matching signed qualification
state from a successful trusted producer.

The security inventory parser reads both legacy flat derivation maps and Nix's
version-4 envelope. It resolves shortened store paths, `inputs.drvs`, direct
structured attributes and fixed outputs whose path is recorded only in the
builder environment. Invalid records, versions and missing requested identities
fail with an explicit error instead of producing incomplete evidence.

The `maestro-ci-route` command emits one versioned JSON route plan. Focused
qualification, protected-main publication, and the required verdict all
consume that exact output, so downstream jobs cannot independently reinterpret
classification or reuse state. Both the router and verdict validate
`nix/automation/qualification-plan.schema.json`; schema-v3 rejects undeclared
fields, invalid Nix graph digests, and publication without qualification.
The path policy decides whether a change can affect the appliance. When it
can, `lib.ciQualificationInputs.x86_64-linux` supplies separate canonical Nix
graphs for installer media and supply evidence instead of maintaining another
source-path approximation.
Media reuse binds the evaluated ISO store path, embedded appliance roots, and
boot-test policy. Changes to CI tools can refresh evidence while reusing an
unchanged, previously booted ISO. Installer recipe or boot-policy changes still
invalidate qualification.

Before media/evidence qualification, the XO cache preflight copies the full
locked closure from an approved cache with normal signature verification and no
builders. Metadata alone is insufficient: an advertised output may reference a
deleted NAR. An incomplete upstream cache tries the Maestro mirror; if neither
can supply the closure, qualification stops with a cache-repair diagnostic.
Repair or republish through the admitted upstream publication flow. Do not
disable OpenSSL tests or replace the locked XO build to hide a cache failure.
Temporary upstream security overrides should be retired once XO's own Nixpkgs
pin provides the required version and the resulting Node/runtime outputs have
been qualified. Updating that upstream pin is an independent package release;
Maestro consumes its verified handoff rather than replacing XO's libraries via
a downstream override.
Pull requests and pushes fetch full history for path classification;
scheduled and manual validation use the default shallow checkout. Dormant
merge-group support accepts a diff only when both event SHAs exist and the base
is an ancestor of the head, otherwise it requires installer validation.

The `validation`, `media`, `evidence`, and `publish` target sets are versioned
pure values under `lib.ciPlans.x86_64-linux`. Maestro builds them with the validator supplied by its
locked Xen Orchestra input. The schema-v2 runner rejects malformed or duplicate
targets before building, runs each target in a fresh child process against
the shared Nix store, and collects every failure before it exits.

For a focused Rust edit:

```bash
devenv shell -- bash -lc \
  'cd pkgs/maestro-menu && cargo fmt --check && cargo check --locked && cargo test --locked'
```

The flake exposes separate cached checks for automation, qualification-input,
release, operator, and Secretspec contracts, plus ShellCheck, workflow policy
(`actionlint`, `zizmor`, and YAML-aware assertions), and repository invariants.
This keeps failures focused while `ci:repository-audit` runs the complete flake and
formatting contracts. Run focused fixtures through devenv, then finish with
the full task graph.

## Cache behavior

The cache layers have separate responsibilities:

- Cachix stores Nix derivation outputs and shares them between jobs and runs.
- The immutable `maestro-installer` artifact stores the tested ISO, SPDX and
  CycloneDX SBOMs, checksums, attestable state, and artifact pointer.
- The immutable, normally compressed `maestro-evidence` artifact separately
  stores the JSON system SBOMs, XO supply documents, checksums, and
  qualification state. The combined artifact remains uncompressed by GitHub
  because its ISO is already compressed.

Metadata-only XO handoff checks read an absent local output's identity from
Maestro, XO and NixOS public cache metadata. Only a 404 advances to the next
cache; unavailable or malformed metadata blocks. The first observed hash must
still match the exact checked handoff policy. This uses the consumer's existing
pinned cache set and does not restore a closure or grant publication authority.

Qualification has five deliberately distinct outcomes:

- `skip` means the change cannot affect the appliance.
- `reuse` points at an artifact whose media and evidence identities both match.
- `refresh-evidence` downloads the matching, already-booted ISO and regenerates
  only the system/XO inventories, checksums, and attestations.
- `qualify-media-reuse-evidence` realizes and boots new media, then validates
  and re-attests matching cached evidence without executing `sbomnix`.
- `qualify-media` realizes the ISO, boots it, and then generates its evidence.

The media plan contains only `installer-iso`; the evidence plan contains only
the appliance closure, `sbomnix`, Xen Orchestra, and its supply assertion.
The installer explicitly uses SquashFS `zstd` compression level 1 instead of
nixpkgs' much slower inherited level 19. This intentionally favors fast CI and
qualification over the smallest possible ISO; release assets remain split
below GitHub's per-file size limit. The measured installer moved from 2.491 GB
to 2.892 GB (about 16%); qualification enforces a 3.0 GB ISO budget.
GitHub Actions resets Nix's base substituter to `cache.nixos.org`; the flake's
public Cachix `extra-substituters` are then applied normally. The required
verdict runs the packaged `ci:verdict` task through Nix/devenv, validates the
schema-v3 route contract, and checks required scanning and protected-main
signing results.

Before validation or installer construction, an inventory preflight decodes a
real derivation returned by the active Nix CLI. Run it separately with
`devenv tasks run ci:security:inventory-preflight`. This catches metadata format
incompatibilities before an expensive media build. The pinned devenv launcher
also includes literal coreutils patches in its closure, so substitution does
not leave the native evaluator's build-time source paths unmaterialized.

Protected-main publication now includes `maestro-ci-toolchain` (the pinned
devenv launcher and plan runner) and `sbomnix`, in addition to the five appliance
and operator targets. Their exact signed closures can be substituted on later
runners. Publication still runs only after qualification, scanning and signing;
PR jobs receive no cache write credentials. A cold runner may still build when
the exact output has not yet been published.

CI scans products in the qualification builder, where their Nix closures are
already available. Its security job validates and attests that run's native
report. Release scans restore the exact completed CI candidate's authenticated
transport before reading installed files. This qualification restore verifies
producer provenance and output identities; public distribution still requires
the separate human admission checks.

Release inventories use `maestro-evidence` from the assembled inventory's
`artifact_run_id`. Weekly scanning uses
`maestro-ci-download-installer DIRECTORY evidence`. This preserves the same
signed pointer, producer, checksum and evidence attestation checks without
transferring the ISO. The downloader's default and release publication retain
full media verification, including the ISO's SPDX predicate binding. The
original `evidence_run_id` selects retained transport when qualification reuses
older product bytes; it must not replace `artifact_run_id` when selecting the
current assembled inventory and scanner report.

`maestro-ci-trusted-run --batch` accepts a nonempty array of
`{"run_id":123,"source_sha":"<40-character commit or empty string>"}` on stdin.
It fetches each producer once, takes one protected-main snapshot, and checks
each unique ancestry once. It validates every requested source constraint and
returns metadata in request order. Reuse ends when the command exits; no trust
decision persists between jobs or scans.

Maestro uses `https://maestro.cachix.org` for its own binary cache. Native
`devenv` also pulls from `xen-orchestra-ce`, `devenv` and `nix-community`.
The flake, installed appliance, installer and first-install commands trust the
same public signing keys. Public pulls do not require publishing credentials.

GitHub protected-main publication reads repository secret
`CACHIX_MAESTRO_AUTH_TOKEN` and variable `CACHIX_MAESTRO_PUBKEY`. SecretSpec
profiles declare both names; publishing checks the supplied public key against
the reviewed key and maps the dedicated token to Cachix's `CACHIX_AUTH_TOKEN`
only at runtime. The destination is always `maestro`.

For the recommended interactive SecretSpec setup, create a per-cache Cachix
write token in the Maestro cache settings, then run from this checkout:

```bash
cp -n devenv.local.yaml.example devenv.local.yaml
unset CACHIX_AUTH_TOKEN
nix run --accept-flake-config .#devenv -- shell
```

Inspect an existing local override before merging the example into it. On the
first interactive run Devenv prompts for `CACHIX_MAESTRO_DEVENV_TOKEN` and saves
it in the system keyring. Paste only the token value. The keyring must be
available and unlocked in this login session. Exit the shell after testing;
subsequent runs can resolve the saved value without prompting. `direnv` and
noninteractive Actions cannot perform this initial prompt.

Check the saved token without displaying it:

```bash
nix run --accept-flake-config .#devenv -- tasks run --mode single cache:doctor
```

The read-only diagnostic reports the expected cache, whether its public signing
key matches, and the API permission (`Read`, `Write`, or `Admin`). It exits
successfully only for matching `Write` or `Admin` access. Public read permission
does not establish token validity. It cannot enumerate all grants or identify a
token's creator; use Cachix token settings for those details. The diagnostic
never uploads anything, follows redirects, prints tokens or raw error bodies,
or treats permissions as publication approval.

The local example uses Devenv's built-in `devenv-cachix/default` namespace,
independent of the project's `maestro` namespace and its existing publication
token. No built-in token declaration belongs in `secretspec.toml`. The
`development` profile inherits only public defaults. Optional credential
contracts formerly in `default` now live in the explicitly selected `runtime`
profile; named publication, authority, queue, and deployment profiles retain
their contracts. The root config disables implicit project-secret resolution.
Token values must never be referenced by Nix modules or derivations.

Maestro remains a flake: `nix run .#devenv` selects the locked native CLI and
`devenv shell` uses the native task graph. `nix develop --accept-flake-config`
shares the package definition, but does not run the CLI's SecretSpec prompt or
native Cachix manager. Adding `--impure` does not enable those features. CI
installs Nix and runs the same locked CLI and declared tasks on ephemeral
GitHub-hosted runners. It uses public cache pulls with no Cachix token or local
override; separately credentialed publication resolves secrets only at runtime.
No Devenv Cloud account or GitHub app is required. This follows the native
[SecretSpec cache setup](https://devenv.sh/binary-caching/) and
[GitHub Actions guidance](https://devenv.sh/integrations/github-actions/) while
retaining the repository's reviewed task and publication boundaries.

Native `cachix.push` stays unset: its observer can queue shell/tool outputs
before an authority task and does not reliably observe nested Nix subprocesses.
Explicit publication still requires fresh product approval, authenticated
`DECISION_PRODUCT` and `DECISION_SCANS`, and verified public readback. A saved
local token does not authorize or repair a release. Existing explicit
`local-publish` / `workstation-pass` contracts remain available to authorized
publication commands; this interactive setup does not migrate those credentials.

Vulnerability findings remain in the documented report stage until fresh
inventory, source-bound dispositions, runtime validation and disposable lab
acceptance pass. These performance changes do not establish those prerequisites.

Critical triage now runs through the shared XO applicability evaluator. The
scanner preserves `findings.json` and emits `critical-applicability.json` plus
`effective-policy.json`; the latter combines still-valid human decisions with
fresh exact machine decisions. The report binds its inventory, rules, evaluator
and runtime context. Reviewed rules expire within 30 days and require exact
advisory, component, derivation, source and patch evidence. npm rules also need
the installed manifest identity and explicit library/consumer code hashes.
Unknown, missing, changed or expired evidence cannot produce an exclusion.

An absent attack surface requires relevant runtime guards in a bound embedded
deployment context. An operating system name, a private management CIDR, the
absence of a currently running process, or caller-supplied configuration alone
does not prove safety. XO supply inventories describe packages and therefore
cannot establish effective appliance configuration. The current reviewed rules
verify nine native fixes; the five npm critical matches remain unresolved.
See [the critical triage record](critical-triage-2026-10-14.md).

To reevaluate a completed scan locally:

```bash
SECURITY_INVENTORY="$PWD" SECURITY_OUTPUT=security-report \
devenv tasks run --mode single ci:security:applicability
```

The default is report mode. `SECURITY_APPLICABILITY_MODE=enforce` is an explicit
local check that fails when critical matches remain unresolved; changing it
does not change the repository's deployment acceptance policy. Malformed or
inconsistent evidence fails in either mode. The regular security scan runs this
boundary automatically and retains the existing high/critical/unscored verdict.

Validation/qualification overlap and event-driven release continuation are
[opt-in orchestration pilots](ci-orchestration-pilots.md). Both default to the
existing path. Historical DAG models are labeled separately from hosted pilot
measurements; real branch dispatches must measure overlap before rollout, and
release continuation must not publish a synthetic release merely to benchmark it.

Deployment templates, metadata, menus, and CLI packages remain covered by the
repository audit and protected-main publication without being redundantly
realized during installer qualification. Reusable evidence is accepted only
from a successful protected-main run while its artifact is unexpired, its state
matches the exact appliance closure identity, and all retained checksums pass.
Forks may not contribute reusable evidence. The scheduled forced run still
performs a complete media qualification before artifact expiry.

Release workflows serialize their orchestration separately from publication.
The Nix-packaged release manager dispatches qualification with a run-scoped CI
identity, so a later `main` push cannot replace the pending release candidate.
Only jobs that can publish acquire the shared `maestro-publication` queue. Its
`queue: max` policy preserves every pending rolling or versioned publication.

`BOOT_TIMEOUT` remains a failure ceiling, not a normal delay: the QEMU smoke
test exits as soon as the installer reaches its readiness marker. The routine
path already completes in under a minute, so qualification policy and target
selection—not a shorter timeout—are the meaningful performance controls.

Only local pure validation tasks use devenv's `execIfModified`. Hosted tasks
always execute and delegate their implementation to flake-packaged programs;
dependency-free tasks run in isolated single-task mode.

The Devenv input follows its upstream default branch; exact revisions remain in
the lockfiles rather than a hand-selected release tag.
Both `flake.lock` and `devenv.lock` are committed. Refresh them together with
the scheduled updater; `nix run .#maestro-ci-lock-validate` verifies
that their shared nixpkgs and devenv pins match. The root Nixpkgs and Home
Manager inputs use FlakeHub's `/0` stable release trains, and Home Manager
follows the root Nixpkgs input. FlakeHub reserves `/0.1` for rolling unstable
releases, so the repository contract rejects either root input moving there.

## Work with changes

Use Jujutsu for local repository work:

```bash
jj status
jj diff
jj describe -m 'type(scope): summary'
jj bookmark set my-change -r @
jj git push --bookmark my-change
```

Protected `main` requires the stable `Required CI verdict`. Maintenance bots and release
automation use narrowly validated pull requests rather than writing around
that protection. See [Project reference](project-reference.md) for the
immutable installer state, caches, SBOMs, attestations, and release flow.

[Back to documentation](index.md)

### Native audit and qualification diagnostics

The existing CI audit uploads `maestro-audit-route` (or the explicitly selected
pilot audit job's artifact) on success and failure. `audit.json` is the native
20-target plan manifest; `timings.json` contains its per-target durations, and
`timings.summary.json` records the final audit phase, exit code and elapsed time.
Early preflight or evaluation failures can have only the summary. The upload
never reruns an audit to obtain missing evidence.

`maestro-qualification-diagnostics` retains assembly stage durations, media and
evidence plan manifests and timings, exact derivation/output identities, and
Nix build logs. The logs record source builds and substitution outcomes; absence
of an event is not proof of a cache hit. `reuse.json` distinguishes requested
inventory reuse, authenticated media reuse and a required new boot. Successful
assembly does not claim a new boot: the existing boot step establishes that.
Inventory reuse still requires the exact evidence input (including distribution
bytes and generator policy), signed state and verified inventory. Input changes
regenerate evidence while unchanged media follows the verified-media route.

Callback job predicates only suppress irrelevant producer branches/events.
Current producer provenance, current main and authority remain authenticated by
the existing leaves before any publication write.

Cache permission diagnostics identify their HTTP client explicitly so Cachix's
edge service does not reject Python's default user-agent. A Cloudflare non-JSON
403 reports `cache-request-blocked`, rather than implying the stored token was
rejected. Credential and API response bodies remain withheld.

### Hosted decision byte reuse observations

Authority, decision reconciliation, publication and disposable consumer jobs
retain `maestro-decision-byte-reuse-<job>` artifacts from their existing native
execution. Each JSONL row contains only a verified public Git blob identity,
byte count, and whether those bytes were reused or supplied by fresh inline
metadata. The artifact excludes proposal contents and all review, membership
and authorization results. Current main, reviews, team membership and every
write gate remain fresh. Use these observations to verify production reuse;
compare equivalent hosted runs before making performance claims.

### Admitted rolling publication metadata

The existing publication `candidate_run` selector reads current protected
admission records before fetching an admitted rolling producer's digest-bound
metadata. Its run, attempt, workflow, producer revision and product source
must match the latest completed native producer. Missing, superseded or
ambiguous admission blocks this explicit selection. The normal publication
gate still checks current human authority and freshness before any write.

Destination inspection precedes closure transport. A matching public cache
therefore needs no full Actions report or retained closure payload merely to
discover its product identity. Fresh official maintenance and security-review
inputs retain their existing authenticated report route, including covered
observations that require no new security decision.

### Published cache upstreams

Configure Maestro Cachix upstreams with `cache.nixos.org` and
`xen-orchestra-ce.cachix.org`. Hosted builds also use Devenv and nix-community,
but delegating published dependencies to those caches makes Cachix skip paths
that the disposable consumer cannot fetch. If push reports nothing to upload
while native closure readback remains partial, compare these settings before
resuming native recovery. See [Cachix upstream selection](https://blog.cachix.org/posts/2025-12-15-configurable-upstream-caches/).

The cache doctor reports observed public permission metadata. A `Read` response
does not establish whether the supplied token can write; keep credential values
in SecretSpec/provider prompts and use native publication receipts as delivery
evidence.

### Publication diagnostics

`MAESTRO_CI_DIAGNOSTICS=true` opts native publication commands into allowlisted
JSON summaries capped at 4096 UTF-8 bytes per record. Default command output,
saved reports, decision packets and publication receipts retain their full
formats. CI enables the mode in both publication controllers and shows the
native cache verification fast-path message.

Each invocation retains its full structured results under
`$RUNNER_TEMP/publication-diagnostics`. The `release:diagnostics` task finalizes
a manifest with event source, checked-out controller commit/tree, run, attempt,
and every file's SHA256 and size. An always-running upload retains these files
on success and failure as `maestro-publication-diagnostics-JOB-RUN-ATTEMPT`.
Finalization reads existing evidence; it never repeats an audit or publication.
Failed destination inspections preserve their original exit status and full
observation, and cannot emit successful GitHub step outputs.

Measurements count native gate invocations, instrumented GitHub API wrapper and
transport process invocations, public destination curl invocations, immutable
Git bytes reused, and emitted JSON-summary bytes. Per-process counters are
cumulative; the manifest takes each process's maxima before summing them.
HTTP attempts remain explicitly unavailable because gh and curl can retry
internally. Summary durations are elapsed monotonic process time; overlapping
observations must not be added as independent stage durations. These are
measurements, not authorization caches or savings estimates. Exception argv,
environment values and HTTP authorization headers are excluded from CI error
records and public summaries.
