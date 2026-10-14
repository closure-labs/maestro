<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development

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

Native SecretSpec uses the env provider and optional `github` profile, with an
explicit hosted access reason. Secrets remain runtime inputs; repository Nix
modules do not copy `secretspec.secrets` into derivations. Credential-free
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

CI and release security jobs download `maestro-evidence` from the assembled
inventory's `artifact_run_id`. Weekly scanning uses
`maestro-ci-download-installer DIRECTORY evidence`. This preserves the same
signed pointer, producer, checksum and evidence attestation checks without
transferring the ISO. The downloader's default and release publication retain
full media verification, including the ISO's SPDX predicate binding. The
original `evidence_run_id` can identify older evidence and must not select the
assembled inventory downloaded for scanning.

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

For local validation with cache publication, resolve the workstation `pass`
references declared by SecretSpec's `local-publish` profile:

```bash
SECRETSPEC_REASON='Validate and populate the Maestro cache' \
nix run --accept-flake-config .#secretspec -- run --provider workstation-pass \
  --profile local-publish \
  --scope cachix -- devenv tasks run ci:cache-validation
```

The explicit provider overrides an unrelated global `SECRETSPEC_PROVIDER`.
The profile reads `cachix/maestro/auth_token` and the public-key entry
`cachix/maestro`. A multiline configuration entry must supply the exact public
key as the resolved value; other configuration belongs outside that entry.
The equivalent explicit runtime environment is:

```bash
CACHIX_MAESTRO_AUTH_TOKEN="$(pass show cachix/maestro/auth_token)" \
CACHIX_MAESTRO_PUBKEY="$(pass show cachix/maestro)" \
SECRETSPEC_REASON='Validate and populate the Maestro cache' \
devenv tasks run ci:cache-validation
```

This runs the complete repository audit, records exact output roots in
`$DEVENV_STATE/maestro-validation.json`, and pushes their closures to Maestro.
Credentials never enter Nix evaluation. The cache task rejects hosted execution,
failed or incomplete manifests, missing store outputs and a mismatched public
key. `MAESTRO_CI_AUDIT_MANIFEST` optionally selects another runtime manifest path
for both tasks. Ambient generic Cachix credentials cannot select a different
publication identity or destination.

GitHub's API returns repository variable values but only metadata for Actions
secrets. `gh` can dispatch a remote workflow that uses those secrets; it cannot
resolve their values for a local process. Store a separately authorized local
token or an existing workstation credential in `pass` instead.

`cachix.push = "maestro"` in `devenv.local.nix` observes devenv's own native builds
when its runtime token is supplied as `CACHIX_AUTH_TOKEN`. To enable this optional
observer as well as the explicit task with the same SecretSpec credential,
replace the command after `--scope cachix --` above with:

```bash
bash -c 'export CACHIX_AUTH_TOKEN="$CACHIX_MAESTRO_AUTH_TOKEN"; exec devenv tasks run ci:cache-validation'
```

Repository defaults enable public pulls
and use explicit audited publication. The native push observer does not
reliably observe the audit's nested Nix subprocess builds; the explicit
cache task publishes those exact completed outputs instead. After aggressive
store cleanup, realize `.#maestro-ci-toolchain` before retrying if evaluation
reports a missing `cabal2nix` derivation: an upstream import-from-derivation
reference can outlive its collected producer metadata.

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

Validation/qualification overlap and event-driven release continuation remain
benchmarking work: they change runner cost or orchestration and are not required
to avoid unnecessary ISO downloads and repeated API calls. Hosted runs must
measure the elapsed-time improvement after rollout.

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
