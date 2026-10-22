#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
: "${MAESTRO_CI_CLASSIFY:?MAESTRO_CI_CLASSIFY must point to the packaged classifier}"
: "${MAESTRO_CI_CLASSIFY_PATHS:?MAESTRO_CI_CLASSIFY_PATHS must point to the packaged path classifier}"
: "${MAESTRO_CI_BOOT_MEDIA:?MAESTRO_CI_BOOT_MEDIA must point to the packaged media boot test}"
: "${MAESTRO_CI_VERDICT:?MAESTRO_CI_VERDICT must point to the packaged verdict}"
: "${MAESTRO_CI_LOCK_VALIDATE:?MAESTRO_CI_LOCK_VALIDATE must point to the packaged lock validator}"
: "${MAESTRO_CI_ROUTE:?MAESTRO_CI_ROUTE must point to the packaged work router}"
: "${MAESTRO_CI_RESOLVE_QUALIFICATION:?MAESTRO_CI_RESOLVE_QUALIFICATION must point to the packaged qualification resolver}"
: "${MAESTRO_CI_QUALIFICATION_INPUTS:?MAESTRO_CI_QUALIFICATION_INPUTS must point to the packaged input resolver}"
: "${MAESTRO_CI_RELEASE_NOTES:?MAESTRO_CI_RELEASE_NOTES must point to the packaged notes extractor}"
: "${MAESTRO_CI_RELEASE_VERSION:?MAESTRO_CI_RELEASE_VERSION must point to the packaged version selector}"
: "${MAESTRO_CI_TRUSTED_UPDATE:?MAESTRO_CI_TRUSTED_UPDATE must point to the packaged trusted updater}"

test_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/maestro-ci-helpers.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

[[ $(printf '%s\n' README.md docs/ci.md VERSION packer/build.sh modules/outputs/checks.nix modules/outputs/dev-shells.nix nix/checks/repository-policy.nix | "$MAESTRO_CI_CLASSIFY_PATHS") == false ]]
[[ $(printf '%s\n' modules/_nixos/platform.nix | "$MAESTRO_CI_CLASSIFY_PATHS") == true ]]
[[ $(printf '%s\n' nix/ci-plans.json | "$MAESTRO_CI_CLASSIFY_PATHS") == true ]]
[[ $(printf '%s\n' nix/automation/qualification-assets.sh | "$MAESTRO_CI_CLASSIFY_PATHS") == true ]]
[[ $(printf '%s\n' .github/workflows/ci.yml | "$MAESTRO_CI_CLASSIFY_PATHS") == true ]]
[[ $(printf '%s\n' nix/automation/github/main-ruleset.json | "$MAESTRO_CI_CLASSIFY_PATHS") == false ]]
[[ $(printf '%s\n' future/unknown-output | "$MAESTRO_CI_CLASSIFY_PATHS") == true ]]

merge_fixture="$temporary/merge-group"
mkdir -p "$merge_fixture/docs" "$merge_fixture/modules/_nixos"
git -C "$merge_fixture" init -q
git -C "$merge_fixture" config user.email fixture@example.invalid
git -C "$merge_fixture" config user.name Fixture
printf 'fixture\n' >"$merge_fixture/README.md"
git -C "$merge_fixture" add README.md
git -C "$merge_fixture" commit -qm root
merge_base=$(git -C "$merge_fixture" rev-parse HEAD)
printf 'irrelevant\n' >"$merge_fixture/docs/irrelevant.md"
git -C "$merge_fixture" add docs/irrelevant.md
git -C "$merge_fixture" commit -qm irrelevant
irrelevant_head=$(git -C "$merge_fixture" rev-parse HEAD)
printf '{}\n' >"$merge_fixture/modules/_nixos/merge-group-fixture.nix"
git -C "$merge_fixture" add modules/_nixos/merge-group-fixture.nix
git -C "$merge_fixture" commit -qm relevant
relevant_head=$(git -C "$merge_fixture" rev-parse HEAD)
git -C "$merge_fixture" switch -q --detach "$merge_base"
mkdir -p "$merge_fixture/docs"
printf 'divergent\n' >"$merge_fixture/docs/divergent.md"
git -C "$merge_fixture" add docs/divergent.md
git -C "$merge_fixture" commit -qm divergent
divergent_head=$(git -C "$merge_fixture" rev-parse HEAD)

classifier_env=(
  EVENT_NAME=merge_group
  MAESTRO_INSTALLER_POLICY="$test_root/nix/automation/installer-policy.json"
  MAESTRO_SYSTEM_ROOT="$merge_fixture"
)
[[ $(env "${classifier_env[@]}" MERGE_BASE_SHA="$merge_base" MERGE_HEAD_SHA="$irrelevant_head" "$MAESTRO_CI_CLASSIFY") == false ]]
[[ $(env "${classifier_env[@]}" MERGE_BASE_SHA="$merge_base" MERGE_HEAD_SHA="$relevant_head" "$MAESTRO_CI_CLASSIFY") == true ]]
[[ $(env "${classifier_env[@]}" MERGE_BASE_SHA= MERGE_HEAD_SHA= "$MAESTRO_CI_CLASSIFY" 2>/dev/null) == true ]]
[[ $(env "${classifier_env[@]}" MERGE_BASE_SHA="$irrelevant_head" MERGE_HEAD_SHA="$divergent_head" "$MAESTRO_CI_CLASSIFY" 2>/dev/null) == true ]]

skip_plan='{"schema_version":3,"qualification":{"required":false,"mode":"skip","artifact_run_id":null,"media_run_id":null,"evidence_run_id":null,"media_input":null,"evidence_input":null},"publish_required":false}'
reuse_plan='{"schema_version":3,"qualification":{"required":true,"mode":"reuse","artifact_run_id":42,"media_run_id":41,"evidence_run_id":40,"media_input":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence_input":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"publish_required":true}'
evidence_plan='{"schema_version":3,"qualification":{"required":true,"mode":"refresh-evidence","artifact_run_id":42,"media_run_id":41,"evidence_run_id":42,"media_input":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence_input":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"publish_required":false}'
media_reuse_plan='{"schema_version":3,"qualification":{"required":true,"mode":"qualify-media-reuse-evidence","artifact_run_id":42,"media_run_id":42,"evidence_run_id":40,"media_input":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence_input":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"publish_required":false}'
media_plan='{"schema_version":3,"qualification":{"required":true,"mode":"qualify-media","artifact_run_id":42,"media_run_id":42,"evidence_run_id":42,"media_input":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence_input":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"publish_required":false}'
env ROUTE_RESULT=success SECURITY_RESULT=skipped CI_PLAN="$skip_plan" \
  QUALIFICATION_RESULT=skipped "$MAESTRO_CI_VERDICT"
env ROUTE_RESULT=success SECURITY_RESULT=success CI_PLAN="$reuse_plan" \
  QUALIFICATION_RESULT=success "$MAESTRO_CI_VERDICT"
env ROUTE_RESULT=success SECURITY_RESULT=success CI_PLAN="$evidence_plan" \
  QUALIFICATION_RESULT=success "$MAESTRO_CI_VERDICT"
env ROUTE_RESULT=success SECURITY_RESULT=success CI_PLAN="$media_reuse_plan" \
  QUALIFICATION_RESULT=success "$MAESTRO_CI_VERDICT"
env ROUTE_RESULT=success SECURITY_RESULT=success CI_PLAN="$media_plan" \
  QUALIFICATION_RESULT=success "$MAESTRO_CI_VERDICT"
# Event boundaries: branch qualification never needs signing; protected-main
# qualification requires it, and all required scans must complete successfully.
for event in pull_request merge_group push schedule workflow_dispatch; do
  ref=refs/heads/main
  signing=success
  case $event in
    pull_request) ref=refs/pull/1/merge; signing=skipped ;;
    merge_group) ref=refs/heads/gh-readonly-queue/main/pr-1; signing=skipped ;;
  esac
  env ROUTE_RESULT=success CI_PLAN="$media_plan" QUALIFICATION_RESULT=success \
    SECURITY_RESULT=success SIGNING_RESULT="$signing" GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
    "$MAESTRO_CI_VERDICT"
  if env ROUTE_RESULT=success CI_PLAN="$media_plan" QUALIFICATION_RESULT=success \
    SECURITY_RESULT=failure SIGNING_RESULT="$signing" GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
    "$MAESTRO_CI_VERDICT" >/dev/null 2>&1; then
    echo 'CI verdict accepted a failed dependency scan.' >&2; exit 1
  fi
  if [[ $signing == success ]] && env ROUTE_RESULT=success CI_PLAN="$media_plan" QUALIFICATION_RESULT=success \
    SECURITY_RESULT=success SIGNING_RESULT=skipped GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
    "$MAESTRO_CI_VERDICT" >/dev/null 2>&1; then
    echo 'Protected-main verdict accepted missing signing.' >&2; exit 1
  fi
done

# Speculative qualification must never turn a failed/cancelled overlapping
# audit into a successful required verdict, even when every other job passed.
env ROUTE_RESULT=success CI_PLAN="$media_plan" QUALIFICATION_RESULT=success \
  SECURITY_RESULT=success SIGNING_RESULT=skipped GITHUB_EVENT_NAME=workflow_dispatch \
  GITHUB_REF=refs/heads/pilot AUDIT_OVERLAP=true AUDIT_RESULT=success "$MAESTRO_CI_VERDICT"
for audit_result in failure cancelled skipped; do
  if env ROUTE_RESULT=success CI_PLAN="$media_plan" QUALIFICATION_RESULT=success \
    SECURITY_RESULT=success SIGNING_RESULT=success GITHUB_EVENT_NAME=workflow_dispatch \
    GITHUB_REF=refs/heads/main AUDIT_OVERLAP=true AUDIT_RESULT="$audit_result" \
    "$MAESTRO_CI_VERDICT" >/dev/null 2>&1; then
    printf 'CI verdict accepted missing or failed overlapping audit.\n' >&2; exit 1
  fi
done
if env ROUTE_RESULT=success CI_PLAN="$media_plan" QUALIFICATION_RESULT=success \
  SECURITY_RESULT=success SIGNING_RESULT=success GITHUB_EVENT_NAME=push \
  GITHUB_REF=refs/heads/main AUDIT_OVERLAP=true AUDIT_RESULT=success \
  "$MAESTRO_CI_VERDICT" >/dev/null 2>&1; then
  printf 'CI verdict accepted an unapproved overlap event.\n' >&2; exit 1
fi

invalid_publish_plan='{"schema_version":3,"qualification":{"required":false,"mode":"skip","artifact_run_id":null,"media_run_id":null,"evidence_run_id":null,"media_input":null,"evidence_input":null},"publish_required":true}'
if env ROUTE_RESULT=success SECURITY_RESULT=success CI_PLAN="$invalid_publish_plan" \
  QUALIFICATION_RESULT=skipped "$MAESTRO_CI_VERDICT" >/dev/null 2>&1; then
  printf 'CI verdict accepted publication without an installer lifecycle.\n' >&2
  exit 1
fi
invalid_media_input_plan='{"schema_version":3,"qualification":{"required":true,"mode":"reuse","artifact_run_id":42,"media_run_id":41,"evidence_run_id":40,"media_input":"not-a-digest","evidence_input":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"publish_required":false}'
if env ROUTE_RESULT=success SECURITY_RESULT=success CI_PLAN="$invalid_media_input_plan" \
  QUALIFICATION_RESULT=skipped "$MAESTRO_CI_VERDICT" >/dev/null 2>&1; then
  printf 'CI verdict accepted an invalid media input.\n' >&2
  exit 1
fi
if env ROUTE_RESULT=failure CI_PLAN="$skip_plan" \
  QUALIFICATION_RESULT=skipped "$MAESTRO_CI_VERDICT"; then
  printf 'CI verdict accepted a failed repository audit.\n' >&2
  exit 1
fi
unknown_mode_plan=$(jq -c '.qualification.mode = "future-mode"' <<<"$skip_plan")
if env ROUTE_RESULT=success SECURITY_RESULT=success CI_PLAN="$unknown_mode_plan" \
  QUALIFICATION_RESULT=skipped "$MAESTRO_CI_VERDICT" >/dev/null 2>&1; then
  printf 'CI verdict accepted an unknown qualification mode.\n' >&2
  exit 1
fi
if env ROUTE_RESULT=success SECURITY_RESULT=success CI_PLAN='{"schema_version":3' \
  QUALIFICATION_RESULT=skipped "$MAESTRO_CI_VERDICT" >/dev/null 2>&1; then
  printf 'CI verdict accepted malformed route JSON.\n' >&2
  exit 1
fi

route_output="$temporary/route-output"
env \
  EVENT_NAME=workflow_dispatch \
  GITHUB_EVENT_NAME=workflow_dispatch \
  GITHUB_OUTPUT="$route_output" \
  GITHUB_REF=refs/heads/main \
  VALIDATE_ONLY=true \
  "$MAESTRO_CI_ROUTE"
routed_plan=$(sed -n 's/^plan=//p' "$route_output")
jq -e '
  .schema_version == 3 and
  (.qualification.required | not) and
  .qualification.mode == "skip" and
  (.publish_required | not)
' <<<"$routed_plan" >/dev/null

local_plan=$(
  env \
    EVENT_NAME=workflow_dispatch \
    VALIDATE_ONLY=true \
    "$MAESTRO_CI_ROUTE"
)
jq -e '
  .schema_version == 3 and
  (.qualification.required | not) and
  .qualification.mode == "skip" and
  (.publish_required | not)
' <<<"$local_plan" >/dev/null
[[ ! -e maestro-ci-route.json ]]

# The resolver distinguishes all four qualification routes and rejects
# incomplete, expired, untrusted, mismatched, or corrupt cached evidence.
qualification_bin="$temporary/qualification-bin"
qualification_artifacts="$temporary/qualification-artifacts"
qualification_work="$temporary/qualification-work"
mkdir -p "$qualification_bin" "$qualification_artifacts" "$qualification_work"
cat >"$qualification_bin/nix" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${FAKE_QUALIFICATION_GRAPH:?}"
EOF
cat >"$qualification_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "run list" ]]; then
  jq -r '.id' "${FAKE_QUALIFICATION_ARTIFACTS:?}/77/metadata.json"
  exit 0
fi
if [[ "$1 $2" == "run download" ]]; then
  run_id=$3
  artifact_name=
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir) destination=$2; shift 2 ;;
      --name) artifact_name=$2; shift 2 ;;
      *) shift ;;
    esac
  done
  source_dir="${FAKE_QUALIFICATION_ARTIFACTS:?}/$run_id/$artifact_name"
  [[ -d "$source_dir" && ! -e "$source_dir/.expired" ]]
  cp -R "$source_dir/." "$destination/"
  exit 0
fi
if [[ "$1" == api && "$2" == */artifacts ]]; then
  run_id=${2%/artifacts}
  run_id=${run_id##*/}
  if [[ "$*" == *'maestro-evidence'* ]]; then
    artifact_name=maestro-evidence
  else
    artifact_name=maestro-installer
  fi
  artifact_dir="${FAKE_QUALIFICATION_ARTIFACTS:?}/$run_id/$artifact_name"
  [[ ! -d "$artifact_dir" || -e "$artifact_dir/.expired" ]] || printf '900\n'
  exit 0
fi
if [[ "$1" == api && "$2" == */actions/runs/* ]]; then
  cat "${FAKE_QUALIFICATION_ARTIFACTS:?}/${2##*/}/metadata.json"
  exit 0
fi
if [[ "$1" == api && "$2" == */branches/main ]]; then
  printf '%s\n' '{"protected":true,"commit":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
  exit 0
fi
if [[ "$1" == api && "$2" == */compare/* ]]; then
  printf '%s\n' '{"merge_base_commit":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
  exit 0
fi
if [[ "$1 $2" == 'attestation verify' ]]; then exit 0; fi
exit 1
EOF
sed -i "1c#!${BASH}" "$qualification_bin/nix" "$qualification_bin/gh"
chmod +x "$qualification_bin/nix" "$qualification_bin/gh"

baseline_graph='{"media":{"installer":"/nix/store/media-a"},"evidence":{"system":"/nix/store/system-a"}}'
baseline_inputs=$(MAESTRO_CI_PATH_PREFIX="$qualification_bin" \
  MAESTRO_SYSTEM_ROOT="$qualification_work" \
  FAKE_QUALIFICATION_GRAPH="$baseline_graph" \
  "$MAESTRO_CI_QUALIFICATION_INPUTS")
baseline_media=$(jq -er .media_input <<<"$baseline_inputs")
baseline_evidence=$(jq -er .evidence_input <<<"$baseline_inputs")

reset_qualification_artifacts() {
  rm -rf -- "$qualification_artifacts/77"
  mkdir -p \
    "$qualification_artifacts/77/maestro-qualification-state" \
    "$qualification_artifacts/77/maestro-installer" \
    "$qualification_artifacts/77/maestro-evidence"
  printf '%s\n' '{"id":77,"event":"push","head_repository":{"full_name":"example/maestro"},"status":"completed","conclusion":"success","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","head_branch":"main","path":".github/workflows/ci.yml"}'  \
    >"$qualification_artifacts/77/metadata.json"
  jq -n --arg media_input "$baseline_media" --arg evidence_input "$baseline_evidence" '
    {
      schema_version:5,
      mode:"qualify-media",
      media_input:$media_input,
      evidence_input:$evidence_input,
      source_commit:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      artifact_source_commit:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      media_source_commit:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      producer_event:"push",
      artifact_run_id:77,
      media_run_id:77,
      evidence_run_id:77
    }
  ' >"$qualification_artifacts/77/maestro-qualification-state/maestro-qualification-state.json"
  cp "$qualification_artifacts/77/maestro-qualification-state/maestro-qualification-state.json" \
    "$qualification_artifacts/77/maestro-evidence/maestro-qualification-state.json"
  printf '%s\n' '{"spdxVersion":"SPDX-2.3"}' \
    >"$qualification_artifacts/77/maestro-evidence/maestro-system.spdx.json"
  printf '%s\n' '{"bomFormat":"CycloneDX"}' \
    >"$qualification_artifacts/77/maestro-evidence/maestro-system.cdx.json"
  printf '%s\n' '{"schemaVersion":1}' \
    >"$qualification_artifacts/77/maestro-evidence/xen-orchestra-supply.assertion.json"
  printf '%s\n' '{"spdxVersion":"SPDX-2.3"}' \
    >"$qualification_artifacts/77/maestro-evidence/xen-orchestra-supply.spdx.json"
  printf '%s\n' '{"bomFormat":"CycloneDX"}' \
    >"$qualification_artifacts/77/maestro-evidence/xen-orchestra-supply.cdx.json"
  (
    cd "$qualification_artifacts/77/maestro-evidence"
    sha256sum maestro-system.spdx.json >maestro-system.spdx.json.sha256
    sha256sum maestro-system.cdx.json >maestro-system.cdx.json.sha256
    sha256sum xen-orchestra-supply.assertion.json >xen-orchestra-supply.assertion.json.sha256
    sha256sum xen-orchestra-supply.spdx.json >xen-orchestra-supply.spdx.json.sha256
    sha256sum xen-orchestra-supply.cdx.json >xen-orchestra-supply.cdx.json.sha256
  )
}

resolve_mode() {
  local graph=$1
  local output=$qualification_work/output
  rm -f "$output" "$qualification_work/maestro-qualification-state.json"
  (
    cd "$qualification_work"
    MAESTRO_CI_PATH_PREFIX="$qualification_bin" \
      MAESTRO_SYSTEM_ROOT="$qualification_work" \
      FAKE_QUALIFICATION_GRAPH="$graph" \
      FAKE_QUALIFICATION_ARTIFACTS="$qualification_artifacts" \
      GITHUB_OUTPUT="$output" \
      GITHUB_REPOSITORY=example/maestro \
      GITHUB_RUN_ID=99 \
      GITHUB_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
      "$MAESTRO_CI_RESOLVE_QUALIFICATION" >/dev/null || exit $?
  ) || return $?
  sed -n 's/^mode=//p' "$output"
}

reset_qualification_artifacts
# The timeout fallback starts outside the expired supervisor's environment.
# It must select a normal build without requiring that child's deadline.
[[ $(unset CI_OPERATION_DEADLINE; MAESTRO_RESOLVE_BOUNDED=true ALLOW_REUSE=false resolve_mode "$baseline_graph") == qualify-media ]]
[[ $(resolve_mode "$baseline_graph") == reuse ]]
reset_qualification_artifacts
[[ $(resolve_mode '{"media":{"installer":"/nix/store/media-a"},"evidence":{"system":"/nix/store/system-b"}}') == refresh-evidence ]]
reset_qualification_artifacts
[[ $(resolve_mode '{"media":{"installer":"/nix/store/media-b"},"evidence":{"system":"/nix/store/system-a"}}') == qualify-media-reuse-evidence ]]
reset_qualification_artifacts
[[ $(resolve_mode '{"media":{"installer":"/nix/store/media-b"},"evidence":{"system":"/nix/store/system-b"}}') == qualify-media ]]

route_mode() {
  local graph=$1 event=$2 head_repository=$3 force_build=${4:-false}
  local output=$qualification_work/route-output
  rm -f "$output" "$qualification_work/maestro-qualification-state.json"
  (
    cd "$qualification_work"
    env -u ALLOW_REUSE \
      MAESTRO_CI_PATH_PREFIX="$qualification_bin" \
      MAESTRO_SYSTEM_ROOT="$merge_fixture" \
      MAESTRO_INSTALLER_POLICY="$test_root/nix/automation/installer-policy.json" \
      FAKE_QUALIFICATION_GRAPH="$graph" \
      FAKE_QUALIFICATION_ARTIFACTS="$qualification_artifacts" \
      GITHUB_OUTPUT="$output" \
      GITHUB_REPOSITORY=example/maestro \
      GITHUB_RUN_ID=99 \
      GITHUB_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
      GITHUB_EVENT_NAME="$event" EVENT_NAME="$event" \
      GITHUB_REF=refs/heads/main \
      PR_HEAD_REPOSITORY="$head_repository" \
      PR_BASE_SHA="$merge_base" PR_HEAD_SHA="$relevant_head" \
      MERGE_BASE_SHA="$merge_base" MERGE_HEAD_SHA="$relevant_head" \
      PUSH_BASE_SHA="$merge_base" PUSH_HEAD_SHA="$relevant_head" \
      FORCE_BUILD="$force_build" \
      "$MAESTRO_CI_ROUTE" >/dev/null || exit $?
  ) || return $?
  sed -n 's/^plan=//p' "$output" | jq -er .qualification.mode
}

# Exercise the native event boundary as well as the resolver. A fork must not
# gain artifact imports merely because a reusable protected-main packet exists.
reset_qualification_artifacts
[[ $(route_mode "$baseline_graph" pull_request attacker/fork) == qualify-media ]]
for event in push merge_group workflow_dispatch; do
  reset_qualification_artifacts
  [[ $(route_mode "$baseline_graph" "$event" '') == reuse ]]
done
[[ $(route_mode "$baseline_graph" pull_request example/maestro) == reuse ]]
[[ $(route_mode "$baseline_graph" schedule '') == qualify-media ]]
if route_mode "$baseline_graph" unknown-event ''; then
  echo 'CI routing accepted an unknown producer event.' >&2
  exit 1
fi
[[ $(route_mode "$baseline_graph" pull_request '') == qualify-media ]]
[[ $(route_mode "$baseline_graph" merge_group '' true) == qualify-media ]]
[[ $(route_mode "$baseline_graph" workflow_dispatch '' true) == qualify-media ]]

# The same merge event refreshes evidence without a boot when media is exact,
# but changed media still needs qualification. These are literal input/outcome
# fixtures, using the packaged router, resolver, trust and inventory checks.
[[ $(route_mode '{"media":{"installer":"/nix/store/media-a"},"evidence":{"system":"/nix/store/system-b"}}' merge_group '') == refresh-evidence ]]
[[ $(route_mode '{"media":{"installer":"/nix/store/media-b"},"evidence":{"system":"/nix/store/system-a"}}' merge_group '') == qualify-media-reuse-evidence ]]
reset_qualification_artifacts
rm -rf -- "$qualification_artifacts/77/maestro-installer"
[[ $(route_mode "$baseline_graph" merge_group '') == qualify-media-reuse-evidence ]]
reset_qualification_artifacts
touch "$qualification_artifacts/77/maestro-installer/.expired"
[[ $(route_mode "$baseline_graph" merge_group '') == qualify-media-reuse-evidence ]]
reset_qualification_artifacts
printf 'corrupt\n' >>"$qualification_artifacts/77/maestro-evidence/maestro-system.spdx.json"
if route_mode "$baseline_graph" merge_group ''; then
  echo 'Merge-group routing accepted corrupt qualification evidence.' >&2
  exit 1
fi

reset_qualification_artifacts
rm -rf -- "$qualification_artifacts/77/maestro-evidence"
[[ $(resolve_mode '{"media":{"installer":"/nix/store/media-b"},"evidence":{"system":"/nix/store/system-a"}}') == qualify-media ]]

reset_qualification_artifacts
touch "$qualification_artifacts/77/maestro-evidence/.expired"
[[ $(resolve_mode '{"media":{"installer":"/nix/store/media-b"},"evidence":{"system":"/nix/store/system-a"}}') == qualify-media ]]

reset_qualification_artifacts
printf '%s\n' '{"event":"pull_request","head_repository":"attacker/fork"}' \
  >"$qualification_artifacts/77/metadata.json"
[[ $(resolve_mode "$baseline_graph") == qualify-media ]]

reset_qualification_artifacts
jq '.evidence_input = "state-mismatch"' \
  "$qualification_artifacts/77/maestro-evidence/maestro-qualification-state.json" \
  >"$qualification_work/mismatched-state.json"
mv "$qualification_work/mismatched-state.json" \
  "$qualification_artifacts/77/maestro-evidence/maestro-qualification-state.json"
if resolve_mode '{"media":{"installer":"/nix/store/media-b"},"evidence":{"system":"/nix/store/system-a"}}'; then
  echo 'Invalid authenticated cached evidence became a cache miss.' >&2
  exit 1
fi

reset_qualification_artifacts
printf 'corrupt\n' >>"$qualification_artifacts/77/maestro-evidence/maestro-system.spdx.json"
if resolve_mode '{"media":{"installer":"/nix/store/media-b"},"evidence":{"system":"/nix/store/system-a"}}'; then
  echo 'Invalid authenticated cached evidence became a cache miss.' >&2
  exit 1
fi

read -r version bump < <(printf '%s\n' 'fix: correction' | "$MAESTRO_CI_RELEASE_VERSION" 2.0.0 auto)
[[ "$version $bump" == '2.0.1 patch' ]]
read -r version bump < <(printf '%s\n' 'fix: correction' | "$MAESTRO_CI_RELEASE_VERSION" 1.0 auto)
[[ "$version $bump" == '1.0.1 patch' ]]
read -r version bump < <(printf '%s\n' 'feat(maestro): capability' | "$MAESTRO_CI_RELEASE_VERSION" 2.0.0 auto)
[[ "$version $bump" == '2.1.0 minor' ]]

jq -e --slurpfile policy "$test_root/nix/automation/decision-policy.json" '
  .enforcement == "active" and
  (.bypass_actors | length) == 0 and
  any(.rules[]; .type == "merge_queue" and
    .parameters.merge_method == "MERGE" and
    .parameters.max_entries_to_merge == 1) and
  any(.rules[]; .type == "required_status_checks" and .parameters.strict_required_status_checks_policy == false and
    .parameters.required_status_checks == [
      {context:"Required CI verdict",integration_id:15368},
      {context:"Maintainer decision authority",integration_id:$policy[0].appId},
      {context:"Analyze (actions)",integration_id:15368},
      {context:"Analyze (javascript-typescript)",integration_id:15368},
      {context:"Analyze (python)",integration_id:15368},
      {context:"Analyze (rust)",integration_id:15368}
    ])
' "$test_root/nix/automation/github/main-ruleset.json" >/dev/null
read -r version bump < <(printf '%s\n' 'feat!: incompatible' | "$MAESTRO_CI_RELEASE_VERSION" 2.0.0 auto)
[[ "$version $bump" == '3.0.0 major' ]]
read -r version bump < <(printf '%s\n' 'fix: correction' | "$MAESTRO_CI_RELEASE_VERSION" 2.0.0 minor)
[[ "$version $bump" == '2.1.0 minor' ]]

release_notes=$("$MAESTRO_CI_RELEASE_NOTES" 2.0.0 "$test_root/CHANGELOG.md")
grep -Fq 'clean 2.0' <<<"$release_notes"
grep -Fq 'maestroctl' <<<"$release_notes"
if grep -Fq 'Unreleased' <<<"$release_notes"; then
  printf 'Release notes include the Unreleased section.\n' >&2
  exit 1
fi
historical_notes=$("$MAESTRO_CI_RELEASE_NOTES" 1.1.0 "$test_root/docs/history/legacy-changelog.md")
grep -Fq 'Security' <<<"$historical_notes"
grep -Fq 'Magic Cache' <<<"$historical_notes"
if "$MAESTRO_CI_RELEASE_NOTES" 9.9.9 "$test_root/CHANGELOG.md" >/dev/null 2>&1; then
  printf 'Release notes accepted a missing version.\n' >&2
  exit 1
fi

grep -Fq 'gh release view --json tagName --jq .tagName' \
  "$test_root/nix/automation/release-manager.sh"
if grep -Eq 'secrets\.MERGE_QUEUE_(TOKEN|PAT)|RELEASE_AUTOMATION_LOGIN' \
  "$test_root/.github/workflows/release.yml" \
  "$test_root/.github/workflows/queue-automation.yml" \
  "$test_root/.github/workflows/update-flake-lock.yml" \
  "$test_root/docs/project-reference.md"; then
  printf 'Automation still references a stored personal merge token or external owner.\n' >&2
  exit 1
fi
if grep -Fq "git tag --list 'v[0-9]*.[0-9]*.[0-9]*'" \
  "$test_root/.github/workflows/release.yml"; then
  printf 'Release automation still derives its baseline from unpublished tags.\n' >&2
  exit 1
fi

mkdir -p "$temporary/bin"
export MAESTRO_CI_PATH_PREFIX="$temporary/bin"
printf 'fixture iso\n' >"$temporary/installer.iso"
cat >"$temporary/bin/qemu-img" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$temporary/bin/qemu-system-x86_64" <<'EOF'
#!/usr/bin/env bash
trap 'exit 0' TERM
printf 'maestro-installer login:\n'
sleep 30
EOF
sed -i "1c#!${BASH}" \
  "$temporary/bin/qemu-img" \
  "$temporary/bin/qemu-system-x86_64"
chmod +x "$temporary/bin/qemu-img" "$temporary/bin/qemu-system-x86_64"
PATH="$temporary/bin:$PATH" \
  BOOT_TIMEOUT=20s \
  BOOT_LOG="$temporary/boot.log" \
  timeout 5s "$MAESTRO_CI_BOOT_MEDIA" "$temporary/installer.iso"
grep -Fq 'maestro-installer login:' "$temporary/boot.log"

# The packaged executable is an immutable store file, just like a flake-built
# ISO. A default log beside it would fail before QEMU could start.
mkdir -p "$temporary/boot-logs"
(
  unset BOOT_LOG RUNNER_TEMP
  PATH="$temporary/bin:$PATH" TMPDIR="$temporary/boot-logs" BOOT_TIMEOUT=20s \
    timeout 5s "$MAESTRO_CI_BOOT_MEDIA" "$MAESTRO_CI_BOOT_MEDIA"
)
grep -Fq 'maestro-installer login:' "$temporary/boot-logs/"*.log

cat >"$temporary/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Only merge/queue mutations receive the dedicated token. Every other request
# must retain the job token, including reads, branch refresh and CI dispatch.
if [[ "$1 $2" == 'pr merge' ||
      ( "$1 $2" == 'api graphql' && "$*" == *'enqueuePullRequest(input:'* ) ]]; then
  [[ "$GH_TOKEN" == queue-fixture ]]
else
  [[ "$GH_TOKEN" == fixture ]]
fi
if [[ "$1 $2" == 'pr view' ]]; then
  fake_head=${FAKE_HEAD_SHA:-abc123}
  if [[ ${FAKE_CHANGE_AFTER_WATCH:-false} == true && -e ${FAKE_WATCH_MARKER:-/nonexistent} ]]; then
    fake_head=changed-after-ci
  fi
  if [[ -n ${FAKE_UPDATE_MARKER:-} && -e $FAKE_UPDATE_MARKER ]]; then
    if [[ -n ${FAKE_UPDATE_DELAY_MARKER:-} && ! -e $FAKE_UPDATE_DELAY_MARKER ]]; then
      touch "$FAKE_UPDATE_DELAY_MARKER"
    else
      fake_head=${FAKE_UPDATED_HEAD_SHA:-$fake_head}
    fi
  fi
  fake_state=OPEN
  if [[ ${FAKE_SYNC_WAIT:-false} == true ]] &&
    { [[ -e ${FAKE_ENQUEUE_LOG:-/nonexistent} ]] ||
      [[ ${FAKE_QUEUE_PRESENT:-false} == true && -e ${FAKE_QUEUE_CHECK_LOG:-/nonexistent} ]] ||
      [[ ${FAKE_MERGED_AFTER_WATCH:-false} == true && -e ${FAKE_WATCH_MARKER:-/nonexistent} ]]; }; then
    fake_state=MERGED
  fi
  jq -n \
    --arg author "${FAKE_AUTHOR:-release-bot}" \
    --arg head "$fake_head" \
    --arg state "$fake_state" \
    '{id:"PR_fixture",author:{login:$author},baseRefName:"main",headRefName:"automation/test",headRefOid:$head,headRepository:{nameWithOwner:"example/maestro"},mergeCommit:{oid:"merged123"},mergeStateStatus:"CLEAN",state:$state,title:"Trusted update",url:"https://example.invalid/pr/1"}'
elif [[ "$1 $2" == 'run list' ]]; then
  if [[ -n ${FAKE_DISPATCH_MARKER:-} && ! -e $FAKE_DISPATCH_MARKER ]]; then
    printf '[]\n'
    exit 0
  fi
  run_head=${FAKE_RUN_HEAD_SHA:-abc123}
  run_conclusion=${FAKE_RUN_CONCLUSION:-success}
  run_status=${FAKE_RUN_STATUS:-completed}
  run_id=42
  jq -n \
    --arg conclusion "$run_conclusion" \
    --arg head "$run_head" \
    --arg status "$run_status" \
    --argjson id "$run_id" \
    '[{conclusion:$conclusion,databaseId:$id,headSha:$head,status:$status}]'
elif [[ "$1 $2" == 'run view' ]]; then
  printf '%s\n' "${FAKE_VIEW_HEAD_SHA:-abc123}"
elif [[ "$1 $2" == 'run watch' ]]; then
  [[ "$3" == 42 && "$*" == *'--interval 30 --exit-status'* ]]
  [[ -z ${FAKE_WATCH_MARKER:-} ]] || touch "$FAKE_WATCH_MARKER"
  [[ ${FAKE_CI_FAILURE:-false} != true ]]
elif [[ "$1 $2" == 'pr update-branch' ]]; then
  [[ -z ${FAKE_UPDATE_MARKER:-} ]] || touch "$FAKE_UPDATE_MARKER"
elif [[ "$1 $2" == 'pr merge' ]]; then
  printf '%s\n' "$*" >"$FAKE_MERGE_LOG"
elif [[ "$1 $2" == 'workflow run' ]]; then
  [[ -z ${FAKE_DISPATCH_MARKER:-} ]] || touch "$FAKE_DISPATCH_MARKER"
elif [[ "$1 $2" == 'api graphql' && "$*" == *'enqueuePullRequest(input:'* ]]; then
  [[ "$*" == *'expectedHeadOid: $head'* && "$*" == *'id=PR_fixture'* && "$*" == *'head=abc123'* ]]
  [[ "$*" != *jump* && "$*" != *admin* ]]
  if [[ ${FAKE_REQUIRE_WATCH:-false} == true ]]; then
    [[ -e $FAKE_WATCH_MARKER ]]
  fi
  printf '%s\n' "$*" >"$FAKE_ENQUEUE_LOG"
  jq -n --arg head "${FAKE_QUEUE_REPLY_HEAD:-abc123}" \
    '{data:{enqueuePullRequest:{mergeQueueEntry:{id:"MQ_fixture",pullRequest:{id:"PR_fixture",headRefOid:$head}}}}}'
elif [[ "$1 $2" == 'api graphql' ]]; then
  [[ -z ${FAKE_QUEUE_CHECK_LOG:-} ]] || printf 'checked\n' >>"$FAKE_QUEUE_CHECK_LOG"
  queue_state=${FAKE_QUEUE_STATE:-CLEAN}
  if [[ -n ${FAKE_QUEUE_READY_MARKER:-} && ! -e $FAKE_QUEUE_READY_MARKER ]]; then
    queue_state=BLOCKED
    touch "$FAKE_QUEUE_READY_MARKER"
  fi
  jq -n --arg head "${FAKE_QUEUE_HEAD:-${FAKE_RUN_HEAD_SHA:-abc123}}" \
    --arg state "$queue_state" --argjson present "${FAKE_QUEUE_PRESENT:-true}" \
    '{data:{node:{id:"PR_fixture",headRefOid:$head,isInMergeQueue:$present,mergeStateStatus:$state}}}'
elif [[ "$1" == api && "$*" == *'/actions/runs/42/approve'* ]]; then
  [[ -z ${FAKE_APPROVAL_MARKER:-} ]] || touch "$FAKE_APPROVAL_MARKER"
elif [[ "$1" == api && "$*" == *'/pulls/1/files?'* ]]; then
  printf '%s\n' "${FAKE_FILES:-VERSION}"
elif [[ "$1" == api && "$*" == *'/contents/VERSION?'* ]]; then
  printf '%s\n' "${FAKE_VERSION:-1.2.3}"
elif [[ "$1" == api && "$*" == *'/commits/main'* ]]; then
  printf 'base123\n'
elif [[ "$1" == api && "$*" == *'/compare/base123...abc123'* ]]; then
  printf '%s\n' "${FAKE_MERGE_BASE:-base123}"
else
  printf 'unexpected gh call: %s\n' "$*" >&2
  exit 1
fi
EOF
sed -i "1c#!${BASH}" "$temporary/bin/gh"
chmod +x "$temporary/bin/gh"
trusted_env=(
  CI_POLL_INTERVAL=0
  GH_TOKEN=fixture
  MERGE_QUEUE_TOKEN=queue-fixture
  GITHUB_REPOSITORY=example/maestro
  PR_NUMBER=1
  EXPECTED_BRANCH=automation/test
  EXPECTED_TITLE='Trusted update'
  EXPECTED_AUTHOR='release-bot'
  DEFAULT_BRANCH=main
  EXPECTED_CHANGE_KIND=version
  EXPECTED_VERSION=1.2.3
  FAKE_MERGE_LOG="$temporary/merge.log"
)

# Model the observed green auto-merge request outside the queue. Only explicit
# enqueue makes it merge; sleeps are elided while retaining the bounded loop.
cat >"$temporary/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
sed -i "1c#!${BASH}" "$temporary/bin/sleep"
chmod +x "$temporary/bin/sleep"
sync_env=(
  "${trusted_env[@]}"
  WAIT_FOR_MERGE=true
  FAKE_SYNC_WAIT=true
  FAKE_REQUIRE_WATCH=true
  FAKE_QUEUE_PRESENT=false
  FAKE_WATCH_MARKER="$temporary/watched"
  FAKE_ENQUEUE_LOG="$temporary/enqueue.log"
  FAKE_QUEUE_CHECK_LOG="$temporary/queue-check.log"
)
# A missing queue credential must fail before enabling auto-merge or enqueue.
rm -f "$temporary/merge.log" "$temporary/enqueue.log"
if env PATH="$temporary/bin:$PATH" "${trusted_env[@]}" MERGE_QUEUE_TOKEN= \
  "$MAESTRO_CI_TRUSTED_UPDATE" >"$temporary/missing-queue-token.log" 2>&1; then
  echo 'Trusted update accepted a missing queue token.' >&2; exit 1
fi
[[ ! -e $temporary/merge.log && ! -e $temporary/enqueue.log ]]
grep -Fq 'MERGE_QUEUE_TOKEN must be configured' "$temporary/missing-queue-token.log"
env PATH="$temporary/bin:$PATH" "${sync_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE"
[[ -s $temporary/enqueue.log && -e $temporary/watched ]]
for refusal in FAKE_CI_FAILURE=true FAKE_CHANGE_AFTER_WATCH=true; do
  rm -f "$temporary/enqueue.log" "$temporary/merge.log" "$temporary/watched"
  if env PATH="$temporary/bin:$PATH" "${sync_env[@]}" "$refusal" \
    "$MAESTRO_CI_TRUSTED_UPDATE" >/dev/null 2>&1; then
    printf 'Trusted update accepted failed CI or a changed head after CI.\n' >&2
    exit 1
  fi
  [[ ! -e $temporary/enqueue.log && ! -e $temporary/merge.log ]]
done
rm -f "$temporary/enqueue.log" "$temporary/queue-check.log"
env PATH="$temporary/bin:$PATH" "${sync_env[@]}" FAKE_QUEUE_PRESENT=true \
  "$MAESTRO_CI_TRUSTED_UPDATE"
[[ ! -e $temporary/enqueue.log ]]
rm -f "$temporary/queue-check.log" "$temporary/queue-ready"
env PATH="$temporary/bin:$PATH" "${sync_env[@]}" \
  FAKE_QUEUE_READY_MARKER="$temporary/queue-ready" "$MAESTRO_CI_TRUSTED_UPDATE"
[[ -s $temporary/enqueue.log && $(wc -l <"$temporary/queue-check.log") -ge 2 ]]
rm -f "$temporary/enqueue.log" "$temporary/merge.log" "$temporary/watched"
env PATH="$temporary/bin:$PATH" "${sync_env[@]}" FAKE_MERGED_AFTER_WATCH=true \
  "$MAESTRO_CI_TRUSTED_UPDATE"
[[ ! -e $temporary/enqueue.log && ! -e $temporary/merge.log ]]
rm -f "$temporary/enqueue.log" "$temporary/watched"
if env PATH="$temporary/bin:$PATH" "${sync_env[@]}" FAKE_QUEUE_REPLY_HEAD=wrong \
  "$MAESTRO_CI_TRUSTED_UPDATE" >/dev/null 2>&1; then
  printf 'Trusted update accepted a queue response for another head.\n' >&2
  exit 1
fi

# Async helpers never watch CI. Pending checks stay async; CLEAN exact heads
# enter the protected queue without relying on another auto-merge event.
rm -f "$temporary/enqueue.log" "$temporary/watched"
env PATH="$temporary/bin:$PATH" "${trusted_env[@]}" FAKE_QUEUE_PRESENT=false \
  FAKE_QUEUE_STATE=BLOCKED FAKE_WATCH_MARKER="$temporary/watched" \
  FAKE_ENQUEUE_LOG="$temporary/enqueue.log" "$MAESTRO_CI_TRUSTED_UPDATE"
[[ ! -e $temporary/enqueue.log && ! -e $temporary/watched ]]
env PATH="$temporary/bin:$PATH" "${trusted_env[@]}" FAKE_QUEUE_PRESENT=false \
  FAKE_WATCH_MARKER="$temporary/watched" FAKE_ENQUEUE_LOG="$temporary/enqueue.log" \
  "$MAESTRO_CI_TRUSTED_UPDATE"
[[ -s $temporary/enqueue.log && ! -e $temporary/watched ]]
rm -f "$temporary/bin/sleep"

env PATH="$temporary/bin:$PATH" "${trusted_env[@]}" \
  "$MAESTRO_CI_TRUSTED_UPDATE"
grep -Fq -- '--auto' "$temporary/merge.log"
grep -Fq -- '--merge' "$temporary/merge.log"
grep -Fq -- '--match-head-commit abc123' "$temporary/merge.log"
env PATH="$temporary/bin:$PATH" FAKE_AUTHOR=app/release-bot "${trusted_env[@]}" \
  "$MAESTRO_CI_TRUSTED_UPDATE"
if env PATH="$temporary/bin:$PATH" FAKE_RUN_HEAD_SHA=stale \
  "${trusted_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE" >/dev/null 2>&1; then
  printf 'Trusted update accepted CI for a stale head.\n' >&2
  exit 1
fi
rm -f "$temporary/approved"
env PATH="$temporary/bin:$PATH" \
  FAKE_RUN_CONCLUSION=action_required \
  FAKE_APPROVAL_MARKER="$temporary/approved" \
  "${trusted_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE"
[[ -e $temporary/approved ]]
rm -f "$temporary/dispatched"
env PATH="$temporary/bin:$PATH" \
  FAKE_DISPATCH_MARKER="$temporary/dispatched" \
  "${trusted_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE"
[[ -e $temporary/dispatched ]]
rm -f "$temporary/updated"
rm -f "$temporary/update-delayed"
env PATH="$temporary/bin:$PATH" \
  FAKE_MERGE_BASE=older123 \
  FAKE_RUN_HEAD_SHA=def456 \
  FAKE_UPDATED_HEAD_SHA=def456 \
  FAKE_UPDATE_DELAY_MARKER="$temporary/update-delayed" \
  FAKE_UPDATE_MARKER="$temporary/updated" \
  "${trusted_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE"
[[ -e $temporary/updated ]]
[[ -e $temporary/update-delayed ]]
grep -Fq -- '--match-head-commit def456' "$temporary/merge.log"
if env PATH="$temporary/bin:$PATH" FAKE_AUTHOR=attacker "${trusted_env[@]}" \
  "$MAESTRO_CI_TRUSTED_UPDATE" >/dev/null 2>&1; then
  printf 'Trusted update accepted the wrong author.\n' >&2
  exit 1
fi

version_env=(
  "${trusted_env[@]}"
  EXPECTED_CHANGE_KIND=version
  EXPECTED_VERSION=1.2.3
)
env PATH="$temporary/bin:$PATH" "${version_env[@]}" \
  "$MAESTRO_CI_TRUSTED_UPDATE"
if env PATH="$temporary/bin:$PATH" FAKE_VERSION=1.2.4 "${version_env[@]}" \
  "$MAESTRO_CI_TRUSTED_UPDATE" >/dev/null 2>&1; then
  printf 'Trusted update accepted the wrong VERSION content.\n' >&2
  exit 1
fi
if env PATH="$temporary/bin:$PATH" FAKE_FILES=$'VERSION\nREADME.md' "${version_env[@]}" \
  "$MAESTRO_CI_TRUSTED_UPDATE" >/dev/null 2>&1; then
  printf 'Trusted update accepted an extra version-PR file.\n' >&2
  exit 1
fi

lock_env=(
  "${trusted_env[@]}"
  EXPECTED_CHANGE_KIND=flake-lock
)
env PATH="$temporary/bin:$PATH" FAKE_FILES=$'devenv.lock\nflake.lock' \
  "${lock_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE"
env PATH="$temporary/bin:$PATH" FAKE_FILES=flake.lock \
  "${lock_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE"
if env PATH="$temporary/bin:$PATH" FAKE_FILES=$'flake.lock\nREADME.md' \
  "${lock_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE" >/dev/null 2>&1; then
  printf 'Trusted lock update accepted a non-lockfile change.\n' >&2
  exit 1
fi

cargo_env=("${trusted_env[@]}" EXPECTED_CHANGE_KIND=cargo)
env PATH="$temporary/bin:$PATH" FAKE_FILES=$'pkgs/maestro-menu/Cargo.toml\npkgs/maestro-menu/Cargo.lock' \
  "${cargo_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE"
if env PATH="$temporary/bin:$PATH" FAKE_FILES=$'pkgs/maestro-menu/Cargo.lock\n.github/workflows/ci.yml' \
  "${cargo_env[@]}" "$MAESTRO_CI_TRUSTED_UPDATE" >/dev/null 2>&1; then
  echo 'Trusted Cargo update accepted a workflow change.' >&2; exit 1
fi

"$MAESTRO_CI_LOCK_VALIDATE"

printf 'CI helper fixture checks passed.\n'
