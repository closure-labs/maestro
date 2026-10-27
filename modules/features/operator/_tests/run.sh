#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
readonly TEST_ROOT

# Exact-head approval reads private evidence using the package token while the
# separate App token supplies organization membership and check authority.
yq -e '.permissions.packages == "read"' "$TEST_ROOT/.github/workflows/decision-authority.yml" >/dev/null
# shellcheck disable=SC2016
grep -Fq 'REGISTRY_TOKEN: ${{ github.token }}' "$TEST_ROOT/.github/workflows/decision-authority.yml"
grep -Fq 'oras login ghcr.io' "$TEST_ROOT/modules/ci/authority/_source/decision-check.sh"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

assert_eq() {
  [ "$1" = "$2" ] || fail "expected '$2', got '$1'"
}

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

# Repository-wide identity, shell parsing, hash-update and CI runtime contracts
# run once under repository-policy, shell-lint and automation-fixtures.

# Fixed target resolution.
actual="$(
  MAESTRO_SYSTEM_ROOT="$TEST_ROOT" bash -c '
    source "$MAESTRO_SYSTEM_ROOT/modules/features/operator/cli/_source/lib/common.sh"
    maestro_default_target
    maestro_host_output_name
    maestro_nixos_rebuild_flake_ref
  '
)"
expected="$(
  printf 'maestro\nmaestro\npath:%s#maestro' "$TEST_ROOT"
)"
assert_eq "$actual" "$expected"

# Staging must work in the current feature layout without removed root directories.
mkdir -p "$temporary/managed/host" "$temporary/managed/modules/features/operator" "$temporary/managed/docs"
for file in AGENTS.md CHANGELOG.md README.md flake.lock flake.nix; do
  touch "$temporary/managed/$file"
done
printf '{}\n' >"$temporary/managed/host/menu.nix"
printf '{}\n' >"$temporary/managed/modules/features/operator/example.nix"
printf 'fixture\n' >"$temporary/managed/docs/guide.md"
git -C "$temporary/managed" init -q
actual="$(MAESTRO_SYSTEM_ROOT="$temporary/managed" bash -c '
  source "$1"
  maestro_stage_changes && git -C "$MAESTRO_SYSTEM_ROOT" diff --cached --name-only
' bash "$TEST_ROOT/modules/features/operator/cli/_source/lib/common.sh")"
grep -Fxq 'host/menu.nix' <<<"$actual" || fail "current host configuration was not staged"
grep -Fxq 'modules/features/operator/example.nix' <<<"$actual" || fail "feature implementation was not staged"

# First-install builds use Determinate Systems' unauthenticated bootstrap cache
# rather than the authenticated FlakeHub Cache endpoint.
actual="$(
  MAESTRO_SYSTEM_ROOT="$TEST_ROOT" bash -c '
    source "$MAESTRO_SYSTEM_ROOT/modules/features/operator/cli/_source/lib/common.sh"
    command=()
    maestro_append_first_install_nix_options command
    printf "%s\n" "${command[@]}"
  '
)"
grep -Fxq 'https://install.determinate.systems https://maestro.cachix.org https://xen-orchestra-ce.cachix.org https://devenv.cachix.org https://nix-community.cachix.org' \
  <<<"$actual" \
  || fail "first-install command omits a required binary cache"
grep -Fxq 'cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM= maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0= xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E= devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw= nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs=' \
  <<<"$actual" \
  || fail "first-install command omits a required cache signing key"
if grep -Fxq 'https://cache.flakehub.com' <<<"$actual"; then
  fail "first-install command uses the authenticated FlakeHub Cache endpoint"
fi
grep -Fq '"https://install.determinate.systems"' \
  "$TEST_ROOT/modules/features/installer/_source/default.nix" \
  || fail "installer ISO omits the Determinate bootstrap cache"
grep -Fq 'squashfsCompression = "zstd -Xcompression-level 1";' \
  "$TEST_ROOT/modules/features/installer/_source/default.nix" \
  || fail "installer ISO does not pin fast SquashFS compression"
grep -Fq '"https://maestro.cachix.org"' \
  "$TEST_ROOT/modules/features/installer/_source/default.nix" \
  || fail "installer ISO omits the Maestro Cachix cache"
grep -Fq '"cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM="' \
  "$TEST_ROOT/modules/features/installer/_source/default.nix" \
  || fail "installer ISO omits the Determinate bootstrap cache key"
grep -Fq '"maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0="' \
  "$TEST_ROOT/modules/features/installer/_source/default.nix" \
  || fail "installer ISO omits the Maestro Cachix key"
if grep -Fq '"https://cache.flakehub.com"' "$TEST_ROOT/modules/features/installer/_source/default.nix"; then
  fail "installer ISO uses the authenticated FlakeHub Cache endpoint"
fi
grep -Fq 'applianceToplevel' "$TEST_ROOT/modules/features/installer/_source/default.nix" \
  || fail "installer ISO omits the Maestro appliance closure"
grep -Fq 'maestroMenu' "$TEST_ROOT/modules/features/installer/_source/default.nix" \
  || fail "installer ISO omits maestro-menu"
grep -Fq 'xenOrchestraCe' "$TEST_ROOT/modules/features/installer/_source/default.nix" \
  || fail "installer ISO omits Xen Orchestra"
grep -Fq 'default = "latest";' "$TEST_ROOT/modules/features/xo/options.nix" \
  || fail "Xen Orchestra does not select the latest package channel by default"
# The interpolation must remain literal in the Nix module source.
# shellcheck disable=SC2016
grep -Fq 'packages.x86_64-linux.${config.maestro.xo.channel}' "$TEST_ROOT/modules/features/xo/options.nix" \
  || fail "Xen Orchestra package does not follow the configured channel"
if grep -Fq 'git ls-remote --tags' "$TEST_ROOT/modules/features/operator/menu/_source/backend/action.sh"; then
  fail "XOA update still depends on removed moving channel tags"
fi
grep -Fq '.#packages.x86_64-linux.xen-orchestra-ce' \
  "$TEST_ROOT/modules/features/installer/_source/qualification-assets.sh" \
  || fail "installer workflow does not build Xen Orchestra explicitly"
# The variable reference must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq 'maestro-ci-qualification-cache "$xo_out"' \
  "$TEST_ROOT/modules/features/installer/_source/qualification-assets.sh" \
  || fail "installer workflow does not verify that its Xen Orchestra output is cached"
grep -Fq 'xen-orchestra-supply-protector' \
  "$TEST_ROOT/modules/ci/graph/_lib/plans.json" \
  || fail "installer plan omits the upstream XO supply assertion"
grep -Fq 'relationshipType: "DESCRIBED_BY"' \
  "$TEST_ROOT/modules/features/installer/_source/qualification-assets.sh" \
  || fail "appliance SPDX does not link its XO component to upstream evidence"
# The variable reference must remain literal in the packaged command source.
# shellcheck disable=SC2016
grep -Fq 'check-jsonschema --schemafile "$MAESTRO_SPDX_SCHEMA"' \
  "$TEST_ROOT/modules/features/installer/_source/qualification-assets.sh" \
  || fail "enriched appliance SPDX is not schema validated"
grep -Fq 'DeterminateSystems/determinate-nix-action@61cbfe2efc2d4e7a8a6d56967c3c1058e846c858' \
  "$TEST_ROOT/.github/actions/setup-nix/action.yml" \
  || fail "installer workflow does not pin Determinate Nix to an immutable revision"
if grep -Fq 'magic-nix-cache-action' \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  "$TEST_ROOT/.github/actions/setup-nix/action.yml"; then
  fail "installer workflow still uses the superseded Magic Cache"
fi
if grep -Fq 'cachix/cachix-action@' \
  "$TEST_ROOT/.github/actions/setup-nix/action.yml"; then
  fail "shared setup implicitly publishes runner outputs"
fi
# PR and merge-group execution stays read-only; only protected-main signing has OIDC.
yq -e '
  .jobs.qualification.permissions.contents == "read" and
  .jobs.qualification.permissions."id-token" == null and
  .jobs.qualification.permissions.attestations == "read" and
  .jobs."fix-hashes" == null and
  .jobs.signing.permissions."id-token" == "write" and
  (.jobs.signing.if | contains("refs/heads/main")) and
  (.jobs.signing.if | contains("push"))
' "$TEST_ROOT/.github/workflows/ci.yml" >/dev/null \
  || fail "qualification mixes untrusted builds with privileged signing"
# Security settings access uses only a short-lived token for this repository.
# Keep the GitHub repository expression literal.
# shellcheck disable=SC2016
yq -o=json '.jobs.policy.steps[] | select(.id == "policy-token") | .with' \
  "$TEST_ROOT/.github/workflows/security.yml" | jq -e '
  ."permission-administration" == "read" and
  ."permission-contents" == null and
  .repositories == "${{ github.event.repository.name }}" and
  ."skip-token-revoke" == null and
  ([to_entries[] | select(.key | startswith("permission-")) | .value] | all(. == "read"))
' >/dev/null \
  || fail "security policy token is not repository-scoped and read-only"
grep -Fq 'determinate-nixd fix hashes --auto-apply' \
  "$TEST_ROOT/modules/features/development/_source/fix-hashes.sh" \
  || fail "packaged hash fixer does not invoke Determinate Nix"
grep -Fq 'unset GH_TOKEN GITHUB_TOKEN' \
  "$TEST_ROOT/modules/features/development/_source/fix-hashes.sh" \
  || fail "packaged hash fixer exposes the write token during Nix evaluation"
grep -Fq 'substituters = https://cache.nixos.org/' \
  "$TEST_ROOT/.github/actions/setup-nix/action.yml" \
  || fail "shared CI setup does not reset the public substituter baseline"
grep -Fq 'determinate-nixd auth logout' \
  "$TEST_ROOT/.github/actions/setup-nix/action.yml" \
  || fail "shared CI setup does not disable Determinate's authenticated cache injection"
grep -Fq 'sudo tee -a /etc/nix/nix.custom.conf' \
  "$TEST_ROOT/.github/actions/setup-nix/action.yml" \
  || fail "shared CI setup does not override Determinate cache injection"
grep -Fq 'sudo systemctl restart nix-daemon.service' \
  "$TEST_ROOT/.github/actions/setup-nix/action.yml" \
  || fail "shared CI setup does not reload the daemon after overriding its cache configuration"
# The variable reference must remain literal in the composite action source.
# shellcheck disable=SC2016
grep -Fq '[[ $substituters != *cache.flakehub.com* ]]' \
  "$TEST_ROOT/.github/actions/setup-nix/action.yml" \
  || fail "shared CI setup does not reject the authenticated FlakeHub cache"
for workflow in "$TEST_ROOT"/.github/workflows/*.yml; do
  yq -o=json '.jobs' "$workflow" | jq -e --arg workflow "${workflow##*/}" '
    all(to_entries[];
      .key as $job | .value |
      if any(.steps[]?;
        ((.run // "") | test("(^|[[:space:]])nix[[:space:]]")))
      then any(.steps[]?; .uses == "$/.github/actions/setup-nix") or
        ($workflow == "ci.yml" and $job == "retained" and
         any(.steps[]?; .uses == "./controller/.github/actions/setup-nix") and
         (.if | contains("github.event.pull_request.base.ref")))
      else true end)
  ' >/dev/null || fail "Nix job bypasses shared hosted configuration: $workflow"
done
yq -e '.secretspec.enable == false and .secretspec.cachix_auth_token == false' \
  "$TEST_ROOT/devenv.yaml" >/dev/null || fail "public Devenv startup must be credential-free"
yq -e '.secretspec.enable == true and .secretspec.provider == "keyring" and
  .secretspec.profile == "development" and .secretspec.cachix_auth_token == "CACHIX_MAESTRO_DEVENV_TOKEN"' \
  "$TEST_ROOT/devenv.local.yaml.example" >/dev/null || fail "local keyring prompt configuration is missing"
grep -Fq 'DEVENV_MAX_JOBS=%s' "$TEST_ROOT/.github/actions/setup-nix/export-runtime.sh" \
  || fail "native devenv does not share the hosted job budget"
grep -Fq 'DEVENV_CORES=%s' "$TEST_ROOT/.github/actions/setup-nix/export-runtime.sh" \
  || fail "native devenv does not share the hosted core budget"
grep -Fq "'' ci:verdict" \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "required CI verdict does not use its declared task"
yq -e '.jobs.verdict.steps[] | select(.uses == "$/.github/actions/setup-nix")' \
  "$TEST_ROOT/.github/workflows/ci.yml" >/dev/null \
  || fail "required verdict must bootstrap its declared Nix task"
yq -e '.jobs.verdict.timeout-minutes <= 20' "$TEST_ROOT/.github/workflows/ci.yml" >/dev/null \
  || fail "required verdict timeout is not bounded"

grep -Fq "fetch-depth: \${{ contains(fromJSON('[\"pull_request\",\"push\",\"merge_group\"]'), github.event_name) && '0' || '2' }}" \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "route checkout lacks full event history or an immutable dispatch parent"
route_outputs=$(yq -r '.jobs.route.outputs | keys | join(",")' \
  "$TEST_ROOT/.github/workflows/ci.yml")
assert_eq "$route_outputs" plan,graph_jobs,graph_gating,graph_mode,graph_sha256
yq -e \
  '.concurrency.group == "maestro-publication" and
   .concurrency.queue == "max" and
   .concurrency.cancel-in-progress == false' \
  "$TEST_ROOT/.github/workflows/publication.yml" >/dev/null \
  || fail "the durable rolling publication queue is not configured"
yq -e \
  '.concurrency.group == "maestro-release" and .concurrency.cancel-in-progress == false' \
  "$TEST_ROOT/.github/workflows/release.yml" >/dev/null \
  || fail "release orchestration and durable publication do not use distinct queues"
yq -e '.concurrency.group == "maestro-publication" and .concurrency.queue == "max" and .concurrency.cancel-in-progress == false' \
  "$TEST_ROOT/.github/workflows/release-publication.yml" >/dev/null \
  || fail "official and rolling publication do not share the durable queue"
yq -e \
  '.on.workflow_dispatch.inputs.release_candidate.type == "boolean" and
   .on.workflow_dispatch.inputs.release_candidate.default == false and
   (.concurrency.group | contains("inputs.release_candidate")) and
   (.concurrency.group | contains("github.run_id"))' \
  "$TEST_ROOT/.github/workflows/ci.yml" >/dev/null \
  || fail "release qualification can be replaced by an ordinary pending main run"
grep -Fq -- '-f release_candidate=true' \
  "$TEST_ROOT/modules/release/publication/_source/release-manager.sh" \
  || fail "release dispatch does not request an isolated qualification run"
if grep -Fq 'run: nix flake update' \
  "$TEST_ROOT/.github/workflows/update-flake-lock.yml"; then
  fail "flake input refresh bypasses its packaged updater"
fi
grep -Fq 'nix flake update --accept-flake-config' \
  "$TEST_ROOT/modules/features/development/_source/update-locks.sh" \
  || fail "packaged updater does not refresh flake inputs"
grep -Fq '"name": "maestro-validation"' \
  "$TEST_ROOT/modules/ci/graph/_lib/plans.json" \
  || fail "flake does not expose pure CI attribute plans"
grep -Fq 'flake-plan-runner' \
  "$TEST_ROOT/modules/features/installer/_source/qualification-assets.sh" \
  || fail "installer builds bypass the shared schema-v2 plan runner"
grep -Fq -- '--no-build --print-build-logs' \
  "$TEST_ROOT/modules/ci/checks/_source/repository-audit.sh" \
  || fail "complete validation does not separate evaluation from planned builds"
# GitHub and shell expressions must remain literal in the source contract.
# shellcheck disable=SC2016
grep -Fq 'CACHIX_MAESTRO_AUTH_TOKEN: ${{ secrets.CACHIX_MAESTRO_AUTH_TOKEN }}' \
  "$TEST_ROOT/.github/workflows/publication.yml" \
  || fail "protected publication does not receive the Cachix token"
# shellcheck disable=SC2016
grep -Fq '.products[].storePath, .roots[].storePath' \
  "$TEST_ROOT/modules/release/publication/_source/publish.sh" \
  || fail "Cachix publication does not use the attested exact distribution roots"
# Dependabot owns action revisions. Assert the action and immutable pin at its
# call site without duplicating a revision that every update would invalidate.
yq -o=json '.jobs.qualification.steps' "$TEST_ROOT/.github/workflows/ci.yml" | jq -e '
  any(.[]; (.uses // "") | test("^actions/upload-artifact@[0-9a-f]{40}$"))
' >/dev/null \
  || fail "installer qualification does not use an immutable artifact uploader"
# The command substitution must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq 'inputs=$(maestro-ci-qualification-inputs)' \
  "$TEST_ROOT/modules/features/installer/_source/qualification-resolve.sh" \
  || fail "installer workflow does not calculate Nix-owned qualification state"
grep -Fq 'contains(fromJSON' \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "focused qualification does not consume the authoritative route plan"
grep -Fq 'if: fromJSON(steps.graph.outputs.route_plan).qualification.required' \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer state upload does not consume the authoritative route plan"
grep -Fq "'' ci:decision:publication" \
  "$TEST_ROOT/.github/workflows/publication.yml" \
  || fail "publication does not require live human admission"
grep -Fq 'name: maestro-qualification-state' \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer workflow does not publish its immutable state pointer"
grep -Fq 'name: maestro-evidence' \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer workflow does not publish reusable evidence"
grep -Fq 'qualify-media-reuse-evidence' \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer workflow does not route media builds through reusable evidence"
grep -Fq 'MAESTRO_INSTALLER_ARTIFACT_BUDGET_BYTES:-3000000000' \
  "$TEST_ROOT/modules/features/installer/_source/qualification-assets.sh" \
  || fail "installer qualification does not enforce the 3.0 GB artifact budget"
if grep -Fq 'maestro-reusable-cache' "$TEST_ROOT/.github/workflows/ci.yml"; then
  fail "installer workflow still transports a redundant closure cache artifact"
fi
# The variable reference must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq '"$sbomnix_out/bin/sbomnix"' \
  "$TEST_ROOT/modules/features/installer/_source/qualification-assets.sh" \
  || fail "installer workflow does not use the flake-provided sbomnix"
grep -Fq 'maestro-system.spdx.json' \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer workflow does not publish an SPDX SBOM"
grep -Fq 'maestro-system.cdx.json' \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer workflow does not publish a CycloneDX SBOM"
grep -Fq 'xen-orchestra-supply.assertion.json' \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer artifact omits the verified upstream XO evidence"
if grep -RiE 'flakehub-push|PUBLICATION_DESTINATION: flakehub|PUBLICATION_STEP: flakehub' "$TEST_ROOT/.github/workflows"; then
  fail "FlakeHub publication remains configured"
fi
grep -Fq -- '--status success' \
  "$TEST_ROOT/modules/features/installer/_source/qualification-resolve.sh" \
  || fail "installer state must accept only successful producers"
grep -Fq 'name: Required CI verdict' "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "consolidated CI does not expose a stable verdict"
grep -Fq 'sbom-path: maestro-system.spdx.json' "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer SBOM is not bound by an attestation"
grep -Fq ".#devenv -- tasks run --mode single --option 'packages:pkgs!' '' ci:qualification:boot-media" "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer workflow does not boot the ISO through its declared task"
grep -Fq 'artifact-metadata: write' "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "attestation job lacks current artifact metadata permission"
grep -Fq 'cron: "23 8 1 */2 *"' "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "installer reproducibility is not validated before artifact expiry"
[[ ! -e "$TEST_ROOT/.github/workflows/cache-maestro-menu.yml" ]] \
  || fail "superseded installer workflow still exists"
[[ ! -e "$TEST_ROOT/.github/workflows/validate.yml" ]] \
  || fail "superseded validation workflow still exists"
[[ ! -e "$TEST_ROOT/.github/workflows/flakehub-publish-tagged.yml" ]] \
  || fail "obsolete standalone FlakeHub runner still exists"
grep -Fq 'cron: "17 9 * * 3"' \
  "$TEST_ROOT/.github/workflows/update-flake-lock.yml" \
  || fail "flake input refresh is not scheduled weekly on Wednesday"
grep -Fq ".#devenv -- tasks run --mode single --option 'packages:pkgs!' '' automation:open-lock-update-pr" \
  "$TEST_ROOT/.github/workflows/update-flake-lock.yml" \
  || fail "flake input refresh bypasses the declared PR publisher task"
grep -Fq ".#devenv -- tasks run --option 'packages:pkgs!' '' ci:repository-audit" \
  "$TEST_ROOT/.github/workflows/ci.yml" \
  || fail "validation bypasses the declared repository-audit task"
if grep -Fq 'inputs:' \
  "$TEST_ROOT/.github/workflows/update-flake-lock.yml"; then
  fail "flake input refresh unexpectedly limits the inputs it updates"
fi
grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-dev\.[0-9]+)?$' "$TEST_ROOT/VERSION" \
  || fail "repository version is not a stable or development semantic version"
grep -Fq ".#devenv -- tasks run --mode single --option 'packages:pkgs!' '' release:stage" "$TEST_ROOT/.github/workflows/release.yml" \
  || fail "release workflow does not split oversized installer assets through its declared task"
grep -Fq '2147483648' "$TEST_ROOT/modules/release/publication/_source/release-split.sh" \
  || fail "release staging does not enforce GitHub's per-asset size limit"
grep -Fq 'Release tag %s already exists without a GitHub release.' \
  "$TEST_ROOT/modules/release/publication/_source/release-manager.sh" \
  || fail "release preparation does not reject pre-existing unpublished tags"
# The variable references must remain literal in the trusted-update source.
# shellcheck disable=SC2016
grep -Fq 'if [[ $dispatched == false && $attempt -ge 2 ]]' \
  "$TEST_ROOT/modules/features/development/_source/trusted-update.sh" \
  || fail "trusted updates do not wait for pull-request CI before fallback dispatch"
# The variable references must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq 'Existing release tag points at another source' \
  "$TEST_ROOT/modules/release/publication/_source/publication-assets.py" \
  || fail "release workflow does not reject an incompatible reserved tag"
grep -Fq "'draft': True" "$TEST_ROOT/modules/release/publication/_source/publication-assets.py" \
  || fail "release workflow does not stage assets in a draft"
# The variable reference must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq 'maestro-ci-release-notes "$RELEASE_VERSION" CHANGELOG.md' \
  "$TEST_ROOT/modules/release/publication/_source/release-manager.sh" \
  || fail "release workflow does not use the curated changelog entry"
# The variable reference must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq "'body': notes" \
  "$TEST_ROOT/modules/release/publication/_source/publication-assets.py" \
  || fail "release workflow does not publish curated release notes"
if grep -Fq -- '--generate-notes' "$TEST_ROOT/modules/release/publication/_source/release-manager.sh"; then
  fail "release workflow still substitutes generated notes for the changelog"
fi
grep -Fq 'candidate-state/maestro-qualification-state.json' \
  "$TEST_ROOT/modules/release/publication/_source/release-manager.sh" \
  || fail "release workflow does not resolve the immutable build state"
# The variable reference must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq 'maestro-ci-verify-inventory candidate "$ARTIFACT_SOURCE_COMMIT"' \
  "$TEST_ROOT/modules/release/publication/_source/release-manager.sh" \
  || fail "release workflow does not verify builder attestations"
# The variable reference must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq -- '--signer-workflow "$signer_workflow"' \
  "$TEST_ROOT/modules/features/installer/_source/verify-inventory.sh" \
  || fail "release verification does not constrain the signer workflow"
grep -Fq 'sbom-path: candidate/maestro-system.spdx.json' \
  "$TEST_ROOT/.github/workflows/release.yml" \
  || fail "versioned release filename is not bound to the SPDX SBOM"
grep -Fq ".#devenv -- tasks run --mode single --option 'packages:pkgs!' '' release:prepare" \
  "$TEST_ROOT/.github/workflows/release.yml" \
  || fail "release version changes bypass protected main"
yq -o=json '.jobs.release.steps' "$TEST_ROOT/.github/workflows/release.yml" | jq -e '
  any(.[]; (.uses // "") | test("^actions/download-artifact@[0-9a-f]{40}$"))
' >/dev/null \
  || fail "release publication does not use an immutable artifact downloader"
# The variable reference must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq "'PATCH', {'draft': False}" \
  "$TEST_ROOT/modules/release/publication/_source/publication-assets.py" \
  || fail "release workflow does not publish the verified immutable draft"
# The variable reference must remain literal in the workflow source.
# shellcheck disable=SC2016
grep -Fq 'Start Maestro ${next_version}' \
  "$TEST_ROOT/modules/release/publication/_source/release-manager.sh" \
  || fail "release workflow does not advance the development version"
grep -Fq 'package-ecosystem: github-actions' \
  "$TEST_ROOT/.github/dependabot.yml" \
  || fail "GitHub Actions updates are not managed by Dependabot"
grep -Fq 'package-ecosystem: cargo' \
  "$TEST_ROOT/.github/dependabot.yml" \
  || fail "Dependabot does not monitor the Rust application"
grep -Fq 'directory: /modules/features/operator/menu/_source/frontend' \
  "$TEST_ROOT/.github/dependabot.yml" \
  || fail "Dependabot does not target the Rust manifest directory"
grep -Fq 'applies-to: security-updates' \
  "$TEST_ROOT/.github/dependabot.yml" \
  || fail "Dependabot does not group Rust security updates"
grep -Fq 'devShells.default = pkgs.mkShellNoCC' \
  "$TEST_ROOT/modules/features/development/shell.nix" \
  || fail "flake does not expose its development toolchain"
grep -Fq 'pkgs.cargo' \
  "$TEST_ROOT/modules/features/development/_lib/packages.nix" \
  || fail "development shell does not provide Cargo"
grep -Fq 'devenv shell -- cargo test' \
  "$TEST_ROOT/AGENTS.md" \
  || fail "repository guidance bypasses the flake-provided Rust toolchain"
grep -Fq 'automation/weekly-flake-input-refresh' \
  "$TEST_ROOT/modules/ci/authority/_source/queue.sh" \
  || fail "trusted flake updates are not eligible for the automation queue"
# shellcheck disable=SC2016
yq -e '
  .jobs.enqueue.permissions.actions == "write" and
  .jobs.enqueue.permissions.contents == "write" and
  .jobs.enqueue.permissions."pull-requests" == "write"
' "$TEST_ROOT/.github/workflows/queue-automation.yml" >/dev/null \
  || fail "trusted update validation lacks required dispatch and merge permissions"
grep -Fq '"growpart"' "$TEST_ROOT/modules/features/xcp-ng/guest/service.nix" \
  || fail "installed appliance does not enable cloud-init growpart"
grep -Fq '"resizefs"' "$TEST_ROOT/modules/features/xcp-ng/guest/service.nix" \
  || fail "installed appliance does not resize the grown root filesystem"

# Installed systems keep all public caches and select the patched runtime only.
grep -Fq '"https://install.determinate.systems"' \
  "$TEST_ROOT/modules/features/platform/nix.nix" \
  || fail "installed system omits the Determinate bootstrap cache"
grep -Fq '"https://maestro.cachix.org"' \
  "$TEST_ROOT/modules/features/platform/nix.nix" \
  || fail "installed system omits the Maestro Cachix cache"
grep -Fq 'paths = [patchedDeterminateNix.out]' \
  "$TEST_ROOT/modules/features/platform/nix.nix" \
  || fail "installed system does not isolate the patched Determinate runtime output"

if MAESTRO_SYSTEM_ROOT="$TEST_ROOT" bash -c '
  source "$MAESTRO_SYSTEM_ROOT/modules/features/operator/cli/_source/lib/common.sh"
  maestro_resolve_target_output vm
' >/dev/null 2>&1
then
  fail "legacy vm target still resolves"
fi

# Removed multi-host CLI commands fail explicitly.
for command in add list select-vm; do
  if MAESTRO_SYSTEM_ROOT="$TEST_ROOT" bash "$TEST_ROOT/modules/features/operator/cli/_source/maestroctl.sh" host "$command" \
    >"$temporary/$command.out" 2>"$temporary/$command.err"
  then
    fail "maestroctl host $command unexpectedly succeeded"
  fi
  grep -q 'was removed' "$temporary/$command.err" \
    || fail "maestroctl host $command did not explain its removal"
done

if MAESTRO_SYSTEM_ROOT="$TEST_ROOT" bash "$TEST_ROOT/modules/features/operator/cli/_source/maestroctl.sh" apply --target vm \
  >"$temporary/target.out" 2>"$temporary/target.err"
then
  fail "apply accepted a target selector"
fi
grep -q 'Target selection was removed' "$temporary/target.err" \
  || fail "apply did not reject target selection clearly"

if bash "$TEST_ROOT/modules/features/installer/_source/bootstrap.sh" --hostname legacy \
  >"$temporary/bootstrap.out" 2>"$temporary/bootstrap.err"
then
  fail "bootstrap accepted legacy hostname selection"
fi
grep -q 'was removed' "$temporary/bootstrap.err" \
  || fail "bootstrap did not reject legacy identity options"

# Packer configuration generation is fixed to one native Maestro template and
# never persists the XCP-ng password.
printf '%s\n' 'ssh-ed25519 AAAATEST operator@example' \
  >"$temporary/operator.pub"
bash "$TEST_ROOT/modules/features/xcp-ng/template/_source/deploy-template.sh" \
  --host 192.0.2.10 \
  --username root \
  --iso-sr "ISO library" \
  --sr "Local storage" \
  --network "Build network" \
  --export-network "Template network" \
  --template-name Maestro \
  --memory-mb 4096 \
  --disk-size-mb 20480 \
  --operator-key "$temporary/operator.pub" \
  --config "$temporary/packer.pkrvars.json" \
  --configure-only
jq -e '
  .remote_host == "192.0.2.10"
  and .remote_username == "root"
  and .sr_iso_name == "ISO library"
  and .sr_name == "Local storage"
  and .network_names == ["Build network"]
  and .export_network_names == ["Template network"]
  and .vm_name == "Maestro"
  and .memory_mb == 4096
  and .disk_size_mb == 20480
  and (.remote_password? == null)
' "$temporary/packer.pkrvars.json" >/dev/null \
  || fail "Packer configuration generation is incorrect"

# The deployer delegates the imperative build to the Nix-packaged builder when
# that executable is supplied, while preserving the checkout and Packer roots.
mkdir -p "$temporary/bin"
# The variable references belong in the generated fake, not this test shell.
# shellcheck disable=SC2016
printf '%s\n' \
  "#!$(command -v bash)" \
  '[[ ${PKR_VAR_remote_password:-} == fixture-password ]] || exit 2' \
  'printf "%s\n" "$@" >"$FAKE_BUILD_ARGS"' \
  'printf "%s\n%s\n" "$MAESTRO_SYSTEM_ROOT" "$MAESTRO_PACKER_ROOT" >"$FAKE_BUILD_ROOTS"' \
  >"$temporary/bin/build-template"
chmod +x "$temporary/bin/build-template"
FAKE_BUILD_ARGS="$temporary/build-template.args" \
FAKE_BUILD_ROOTS="$temporary/build-template.roots" \
MAESTRO_BUILD_TEMPLATE_BIN="$temporary/bin/build-template" \
PKR_VAR_remote_password=fixture-password \
  bash "$TEST_ROOT/modules/features/xcp-ng/template/_source/deploy-template.sh" \
    --operator-key "$temporary/operator.pub" \
    --config "$temporary/packer.pkrvars.json"
grep -Fxq -- "-var-file=$temporary/packer.pkrvars.json" \
  "$temporary/build-template.args" \
  || fail "Packer deployer bypassed the packaged template builder"
expected_roots="$(printf '%s\n%s' "$TEST_ROOT" "$TEST_ROOT/modules/features/xcp-ng/template/_source")"
assert_eq "$(cat "$temporary/build-template.roots")" "$expected_roots"

cat >"$temporary/bin/pass" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == show && $2 == fixture/host ]]
printf 'fixture-password\nusername: root\n'
EOF
sed -i "1c#!${BASH}" "$temporary/bin/pass"
chmod +x "$temporary/bin/pass"
env -u PKR_VAR_remote_password -u XCP_HOSTPASSWORD \
  PATH="$temporary/bin:$PATH" \
  FAKE_BUILD_ARGS="$temporary/build-template.args" \
  FAKE_BUILD_ROOTS="$temporary/build-template.roots" \
  MAESTRO_BUILD_TEMPLATE_BIN="$temporary/bin/build-template" \
  XCP_PASSWORD_PASS_ENTRY=fixture/host \
  bash "$TEST_ROOT/modules/features/xcp-ng/template/_source/deploy-template.sh" \
    --operator-key "$temporary/operator.pub" \
    --config "$temporary/packer.pkrvars.json"

# Exercise the downloaded-media handoff independently of the shared verifier
# (the verifier's rejection cases live in security-contracts.sh).
mkdir -p "$temporary/fake-result/iso"
printf 'fake installer image\n' >"$temporary/fake-result/iso/maestro-installer.iso"
cat >"$temporary/bin/maestro-ci-download-installer" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$1/result-installer/iso"
printf 'fake installer image\n' >"$1/result-installer/iso/maestro-installer.iso"
printf '%s\n' '{"source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' >"$1/selected-state.json"
EOF
cat >"$temporary/bin/nix" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ! ${PKR_VAR_remote_password+x} && ! ${XCP_HOSTPASSWORD+x} && ! ${xcp_password+x} ]]
printf '%s\n' "$@" >"$FAKE_NIX_ARGS"
printf '%s\n' "$FAKE_INSTALLER_RESULT"
EOF
cat >"$temporary/bin/packer" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"$FAKE_PACKER_ARGS"
if [[ $1 == build ]]; then
  [[ ${PKR_VAR_remote_password:-} == fixture-password ]]
  [[ ! ${XCP_HOSTPASSWORD+x} && ! ${xcp_password+x} ]]
  for argument in "$@"; do
    if [[ $argument == bootstrap_private_key_file=* ]]; then
      key=${argument#*=}
      [[ -f $key && $(stat -c %a "$key") == 600 ]]
      printf '%s\n' "$key" >"$FAKE_BOOTSTRAP_PATH"
    fi
  done
else
  [[ ! ${PKR_VAR_remote_password+x} && ! ${XCP_HOSTPASSWORD+x} && ! ${xcp_password+x} ]]
fi
EOF
sed -i "1c#!${BASH}" "$temporary/bin/maestro-ci-download-installer" "$temporary/bin/nix" "$temporary/bin/packer"
chmod +x "$temporary/bin/maestro-ci-download-installer" "$temporary/bin/nix" "$temporary/bin/packer"
PATH="$temporary/bin:$PATH" \
  PKR_VAR_remote_password=fixture-password \
  FAKE_BOOTSTRAP_PATH="$temporary/bootstrap.path" \
  FAKE_PACKER_ARGS="$temporary/packer.args" \
  PACKER_BIN="$temporary/bin/packer" \
  OPERATOR_PUBLIC_KEY_FILE="$temporary/operator.pub" \
  TMPDIR="$temporary" \
  bash "$TEST_ROOT/modules/features/xcp-ng/template/_source/build.sh"
grep -Eq '^iso_url=.*/maestro-installer\.iso$' "$temporary/packer.args" \
  || fail "Packer build did not use the downloaded GitHub artifact"
grep -Fxq 'repo_revision=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$temporary/packer.args" \
  || fail "Packer did not pin the qualified source revision"
[[ ! -e $(cat "$temporary/bootstrap.path") ]] || fail "Packer retained its private bootstrap key"

FAKE_INSTALLER_RESULT="$temporary/fake-result" \
  XCP_HOSTPASSWORD=fixture-password \
  FAKE_NIX_ARGS="$temporary/nix.args" \
  FAKE_BOOTSTRAP_PATH="$temporary/bootstrap.path" \
  FAKE_PACKER_ARGS="$temporary/packer.args" \
  NIX_BIN="$temporary/bin/nix" \
  PACKER_BIN="$temporary/bin/packer" \
  OPERATOR_PUBLIC_KEY_FILE="$temporary/operator.pub" \
  INSTALLER_SOURCE=build \
  REPO_REVISION=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  bash "$TEST_ROOT/modules/features/xcp-ng/template/_source/build.sh"
grep -Fxq "iso_url=$temporary/fake-result/iso/maestro-installer.iso" "$temporary/packer.args" \
  || fail "Packer build did not use the installer directly from the Nix store"
grep -Fxq -- '--accept-flake-config' "$temporary/nix.args" \
  || fail "installer substitution does not accept the flake cache configuration"
grep -Fxq 'output/' "$TEST_ROOT/.gitignore" \
  || fail "installer artifact directory is not ignored"
grep -Fxq '/http_cache.sqlite' "$TEST_ROOT/.gitignore" \
  || fail "sbomnix HTTP cache is not ignored"
grep -Fxq '/sbom.spdx.json' "$TEST_ROOT/.gitignore" \
  || fail "local sbomnix SPDX output is not ignored"

grep -q './packer.nix' "$TEST_ROOT/host/default.nix" \
  || fail "host does not import the dedicated Packer override"
if grep -qE 'PasswordAuthentication|hashedPassword' "$TEST_ROOT/host/packer.nix"; then
  fail "tracked Packer override contains temporary access policy"
fi
grep -q 'refusing to erase a disk without --yes' \
  "$TEST_ROOT/modules/features/installer/_source/install-maestro.sh" \
  || fail "installer does not require explicit destructive confirmation"
grep -q 'mount -t ext4.*root_partition' \
  "$TEST_ROOT/modules/features/installer/_source/install-maestro.sh" \
  || fail "installer does not explicitly mount its ext4 root"
grep -q 'mount -o fmask=0077,dmask=0077.*efi_partition' \
  "$TEST_ROOT/modules/features/installer/_source/install-maestro.sh" \
  || fail "installer does not protect files on the EFI system partition"
grep -q 'cloud-init clean --logs --machine-id --seed' \
  "$TEST_ROOT/modules/features/xcp-ng/template/_source/scripts/seal-template.sh" \
  || fail "Packer sealing does not clear clone identity"
grep -q 'nixos-rebuild --accept-flake-config switch' \
  "$TEST_ROOT/modules/features/xcp-ng/template/_source/scripts/seal-template.sh" \
  || fail "Packer sealing does not accept the flake cache configuration"
grep -q 'maestro_write_apply_state success switch' \
  "$TEST_ROOT/modules/features/xcp-ng/template/_source/scripts/seal-template.sh" \
  || fail "Packer sealing does not record its successful system switch"
grep -qx 'nh clean all' \
  "$TEST_ROOT/modules/features/xcp-ng/template/_source/scripts/seal-template.sh" \
  || fail "Packer sealing does not remove obsolete Nix generations"
grep -q 'last_apply_head=.*git -C /home/maestro/maestro rev-parse HEAD' \
  "$TEST_ROOT/modules/features/xcp-ng/template/_source/scripts/verify-clone.sh" \
  || fail "clone verification does not validate the sealed apply state"
grep -Fq 'd /var/lib/maestro 0755 root root' \
  "$TEST_ROOT/modules/features/operator/account.nix" \
  || fail "the shared Maestro status directory is not operator-readable"
grep -Fq 'd /var/lib/nfs/sm.bak 0755 root root' \
  "$TEST_ROOT/modules/features/xo/storage.nix" \
  || fail "NFS notification state is not created before first boot"
grep -Fq 'd /run/maestro-xo-cifs-credentials 0700 root root' \
  "$TEST_ROOT/modules/features/xo/storage.nix" \
  || fail "CIFS credential directory must have a root-owned parent"
grep -q 'org\.freedesktop\.hostname1\.set-hostname' \
  "$TEST_ROOT/modules/features/platform/security.nix" \
  || fail "platform does not authorize DHCP hostname adoption"
grep -q 'passwd --lock maestro' \
  "$TEST_ROOT/modules/features/xcp-ng/template/_source/scripts/seal-template.sh" \
  || fail "Packer sealing does not lock the temporary operator password"
grep -q 'Timed out waiting for the Xen Orchestra HTTPS endpoint' \
  "$TEST_ROOT/modules/features/xcp-ng/template/_source/scripts/verify-template.sh" \
  || fail "Packer verification does not wait for XO HTTPS readiness"
test "$(grep -c 'XO_READINESS_GRACE_SECONDS=240' \
  "$TEST_ROOT/modules/features/xcp-ng/template/_source/builds.pkr.hcl")" -eq 1 \
  || fail "Packer must apply the four-minute XO grace period exactly once"
grep -q 'XO_READINESS_GRACE_SECONDS:-0' \
  "$TEST_ROOT/modules/features/xcp-ng/template/_source/scripts/verify-template.sh" \
  || fail "template verification does not default to immediate XO retries"

# Bootstrap settings generation populates the fixed identity and supplied keys.
mkdir -p "$temporary/generated/host"
MAESTRO_SYSTEM_ROOT="$temporary/generated" bash -c '
  source "'"$TEST_ROOT"'/modules/features/operator/cli/_source/lib/common.sh"
  keys=("ssh-ed25519 AAAATEST operator@example")
  maestro_write_host_settings \
    "$MAESTRO_SETTINGS_FILE" \
    "/home/maestro/maestro" \
    "America/Chicago" \
    "26.05" \
    "Test Operator" \
    "operator@example.com" \
    keys
'
grep -q 'networking.hostName = "maestro";' "$temporary/generated/host/settings.nix" \
  || fail "generated settings do not fix the maestro hostname"
grep -q 'ssh-ed25519 AAAATEST operator@example' "$temporary/generated/host/settings.nix" \
  || fail "generated settings omitted the SSH key"
grep -q 'maestro.xo = {' "$temporary/generated/host/settings.nix" \
  || fail "generated settings omitted XO"
if grep -q 'config.file' "$temporary/generated/host/settings.nix"; then
  fail "generated settings retain the removed handwritten XO configuration option"
fi
test ! -e "$TEST_ROOT/host/config.maestro.toml" \
  || fail "the obsolete handwritten XO configuration still exists"

# TUI writes only the dedicated native-option override module.
cp "$TEST_ROOT/host/settings.nix" "$temporary/generated/host/settings.nix"
cp "$TEST_ROOT/host/menu.nix" "$temporary/generated/host/menu.nix"
MAESTRO_SYSTEM_ROOT="$temporary/generated" bash -c '
  source "'"$TEST_ROOT"'/modules/features/operator/menu/_source/backend/lib.sh"
  keys=("ssh-ed25519 AAAATEST operator@example")
  system_packages=("ripgrep")
  user_packages=("jq")
  services=("tailscale")
  maestro_tui_write_menu \
    true \
    true \
    keys \
    system_packages \
    user_packages \
    services
'
grep -q 'maestro.operator = {' "$temporary/generated/host/menu.nix" \
  || fail "TUI override does not use typed operator options"
grep -q 'extraSystemPackages = \[' "$temporary/generated/host/menu.nix" \
  || fail "TUI override omitted system packages"
grep -q 'enabledServices = \[' "$temporary/generated/host/menu.nix" \
  || fail "TUI override omitted service enables"
if grep -qE 'networking\.hostName|time\.timeZone' "$temporary/generated/host/menu.nix"; then
  fail "TUI override owns durable host identity settings"
fi

cat >"$temporary/xo-tls.toml" <<'EOF'
[[http.listen]]
port = 80

[[http.listen]]
cert = "/etc/ssl/xo/certificate.pem"
key = "/etc/ssl/xo/key.pem"
port = 443
EOF
MAESTRO_SYSTEM_ROOT="$temporary/generated" bash -c '
  source "'"$TEST_ROOT"'/modules/features/operator/menu/_source/backend/lib.sh"
  maestro_tui_xo_tls_enabled "'"$temporary"'/xo-tls.toml"
' || fail "TUI does not detect TLS from the rendered XO configuration"

cat >"$temporary/xo-http.toml" <<'EOF'
[[http.listen]]
port = 80
EOF
if MAESTRO_SYSTEM_ROOT="$temporary/generated" bash -c '
  source "'"$TEST_ROOT"'/modules/features/operator/menu/_source/backend/lib.sh"
  maestro_tui_xo_tls_enabled "'"$temporary"'/xo-http.toml"
'; then
  fail "TUI reports TLS without a certificate and key listener"
fi

cat >"$temporary/default-options.nix" <<'EOF'
{lib, ...}: {
  maestro.operator = {
    sshKeys = lib.mkDefault [
      "ssh-ed25519 AAAATEST operator@example"
    ];
    enableExtras = lib.mkDefault true;
    extraSystemPackages = [];
  };
}
EOF
actual="$(
  MAESTRO_SYSTEM_ROOT="$temporary/generated" bash -c '
    source "'"$TEST_ROOT"'/modules/features/operator/menu/_source/backend/lib.sh"
    maestro_tui_read_bool_file enableExtras "'"$temporary"'/default-options.nix"
    maestro_tui_read_list_file sshKeys "'"$temporary"'/default-options.nix"
    maestro_tui_read_list_file extraSystemPackages "'"$temporary"'/default-options.nix"
  '
)"
assert_eq "$actual" $'true\nssh-ed25519 AAAATEST operator@example'
if grep -q '_ctx\\|deploymentProfile\\|enableXenHardware' "$temporary/generated/host/menu.nix"; then
  fail "TUI override contains legacy host context"
fi

# Verify the exact generated override composes in a complete flake evaluation.
if [ "${MAESTRO_SKIP_EVAL:-0}" != 1 ]; then
  cp -a "$TEST_ROOT" "$temporary/repo"
  cp "$temporary/generated/host/menu.nix" "$temporary/repo/host/menu.nix"
  env XDG_CACHE_HOME="$temporary/cache" nix eval --raw \
    "path:$temporary/repo#nixosConfigurations.maestro.config.system.build.toplevel.drvPath" \
    >/dev/null
fi

printf 'All Maestro shell tests passed.\n'
