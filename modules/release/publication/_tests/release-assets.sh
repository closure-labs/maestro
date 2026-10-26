#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
: "${MAESTRO_CI_QUALIFICATION_INPUTS:?MAESTRO_CI_QUALIFICATION_INPUTS must point to the packaged input resolver}"
: "${MAESTRO_CI_RELEASE_MANAGER:?MAESTRO_CI_RELEASE_MANAGER must point to the packaged release manager}"

: "${MAESTRO_CI_RELEASE_SPLIT:?MAESTRO_CI_RELEASE_SPLIT must point to the packaged release splitter}"

test_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
export MAESTRO_INSTALLER_POLICY="$test_root/modules/ci/authority/_source/installer-policy.json"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/maestro-release-assets.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
# Even an already-prepared stable VERSION needs queue credentials for the
# eventual development update. Refuse before accessing GitHub or mutating it.
if env GITHUB_REF=refs/heads/main GITHUB_SHA=fixture GITHUB_REPOSITORY=example/maestro \
  DEFAULT_BRANCH=main EXPECTED_AUTHOR=github-actions REQUESTED_BUMP=auto \
  MERGE_QUEUE_TOKEN= "$MAESTRO_CI_RELEASE_MANAGER" prepare >"$temporary/missing-release-queue-token.log" 2>&1; then
  echo 'Release preparation accepted a missing queue token.' >&2; exit 1
fi
grep -Fq 'MERGE_QUEUE_TOKEN must be configured before preparing a release' \
  "$temporary/missing-release-queue-token.log"

mkdir -p "$temporary/bin"
cat >"$temporary/bin/nix" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${FAKE_QUALIFICATION_GRAPH:?}"
EOF
sed -i "1c#!${BASH}" "$temporary/bin/nix"
chmod +x "$temporary/bin/nix"
export MAESTRO_CI_PATH_PREFIX="$temporary/bin"
export FAKE_QUALIFICATION_GRAPH='{"media":{"installer":"/nix/store/media"},"evidence":{"system":"/nix/store/system"}}'

printf '0123456789abcdefghijklmno' >"$temporary/installer.iso"
MAESTRO_RELEASE_PART_SIZE=10 \
MAESTRO_RELEASE_ASSET_LIMIT=12 \
  "$MAESTRO_CI_RELEASE_SPLIT" \
    "$temporary/installer.iso" \
    "$temporary/versioned/maestro-v1.1.1.iso" \
    "$temporary/release"

mapfile -t parts < <(find "$temporary/release" -name '*.iso.part-*' -print | sort)
[[ ${#parts[@]} -eq 3 ]]
cat "${parts[@]}" >"$temporary/reconstructed.iso"
cmp "$temporary/installer.iso" "$temporary/reconstructed.iso"
(
  cd "$temporary/versioned"
  sha256sum --check --strict "$temporary/release/maestro-v1.1.1.iso.sha256"
)

# Exercise the combined inventory and release state machine in an isolated Git
# fixture, including the immutable build input and release manifest.
fixture="$temporary/release-state"
mkdir -p "$fixture/candidate/result-installer/iso" "$fixture/candidate-state"
printf '%s\n' '1.1.2' >"$fixture/VERSION"
printf '## [1.1.2] - 2026-10-19\n\nCurated fixture release notes.\n' >"$fixture/CHANGELOG.md"
printf 'fixture installer\n' >"$fixture/candidate/result-installer/iso/maestro-installer.iso"
printf '%s\n' '{"spdxVersion":"SPDX-2.3"}' >"$fixture/candidate/maestro-system.spdx.json"
printf '%s\n' '{"bomFormat":"CycloneDX"}' >"$fixture/candidate/maestro-system.cdx.json"
git -C "$fixture" init -q
git -C "$fixture" add .
git -C "$fixture" -c user.name=fixture -c user.email=fixture@example.invalid \
  commit -qm fixture
source_sha=$(git -C "$fixture" rev-parse HEAD)
qualification_inputs=$(MAESTRO_SYSTEM_ROOT="$fixture" "$MAESTRO_CI_QUALIFICATION_INPUTS")
media_input=$(jq -er .media_input <<<"$qualification_inputs")
evidence_input=$(jq -er .evidence_input <<<"$qualification_inputs")
jq -n \
  --arg media_input "$media_input" \
  --arg evidence_input "$evidence_input" \
  --arg source_commit "$source_sha" \
  --arg artifact_source_commit "$source_sha" \
  '{schema_version:5,mode:"qualify-media",media_input:$media_input,evidence_input:$evidence_input,source_commit:$source_commit,artifact_source_commit:$artifact_source_commit,media_source_commit:$source_commit,producer_event:"push",artifact_run_id:42,media_run_id:42,evidence_run_id:42}' \
  >"$fixture/candidate-state/maestro-qualification-state.json"

inventory_output="$temporary/inventory-output"
(
  cd "$fixture"
  GITHUB_OUTPUT="$inventory_output" \
    MAESTRO_SYSTEM_ROOT="$fixture" \
    SOURCE_SHA="$source_sha" \
    "$MAESTRO_CI_RELEASE_MANAGER" inventory
)
grep -Fxq 'artifact_run_id=42' "$inventory_output"
grep -Fxq "media_input=${media_input}" "$inventory_output"
grep -Fxq "evidence_input=${evidence_input}" "$inventory_output"

(
  cd "$fixture"
  ARTIFACT_RUN_ID=42 \
    ARTIFACT_SOURCE_COMMIT="$source_sha" \
    MEDIA_INPUT="$media_input" \
    EVIDENCE_INPUT="$evidence_input" \
    GITHUB_REPOSITORY=example/maestro \
    GITHUB_RUN_ID=99 \
    MAESTRO_RELEASE_ASSET_LIMIT=12 \
    MAESTRO_RELEASE_PART_SIZE=10 \
    MAESTRO_SYSTEM_ROOT="$fixture" \
    RELEASE_TAG=v1.1.2 \
    RELEASE_VERSION=1.1.2 \
    RUNNER_TEMP="$temporary" \
    SOURCE_SHA="$source_sha" \
    "$MAESTRO_CI_RELEASE_MANAGER" stage
)
jq -e \
  --arg media_input "$media_input" \
  --arg evidence_input "$evidence_input" \
  --arg source_commit "$source_sha" '
    .schema_version == 4 and
    .version == "1.1.2" and
    .tag == "v1.1.2" and
    .media_input == $media_input and
    .evidence_input == $evidence_input and
    .source_commit == $source_commit and
    (.assets.installer.parts | length) > 1 and
    .assets.spdx.name == "maestro-v1.1.2.spdx.json.gz" and
    .assets.cyclonedx.name == "maestro-v1.1.2.cdx.json.gz"
  ' "$fixture/release/release-manifest.json" >/dev/null
grep -Fxq 'Curated fixture release notes.' "$fixture/release/release-notes.md"

# Exercise release qualification dispatch through the same packaged command
# used by GitHub. A release-owned run must not share main's replaceable pending
# slot, and the exact successful run ID must flow back to the release job.
cat >"$temporary/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-} ${2:-}" in
  "api repos/example/maestro/commits/main")
    printf '%s\n' "${FAKE_SOURCE_SHA:?}"
    ;;
  "run list")
    if [[ -e ${FAKE_DISPATCH_MARKER:?} ]]; then
      printf '%s\n' 314
    fi
    ;;
  "workflow run")
    printf '%s\n' "$*" >"${FAKE_WORKFLOW_ARGS:?}"
    if [[ ${3:-} == release.yml ]]; then
      [[ "$*" == *'--ref main -f bump=major -f event_continuation=false'* ]]
    else
      [[ "$*" == *"-f release_candidate=true"* ]]
    fi
    touch "${FAKE_DISPATCH_MARKER:?}"
    ;;
  "run watch")
    [[ "${3:-}" == 314 && "${4:-}" == --exit-status ]]
    touch "${FAKE_WATCH_MARKER:?}"
    ;;
  *)
    printf 'Unexpected gh fixture invocation: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
sed -i "1c#!${BASH}" "$temporary/bin/gh"
chmod +x "$temporary/bin/gh"
dispatch_output="$temporary/dispatch-output"
export FAKE_DISPATCH_MARKER="$temporary/dispatched"
export FAKE_SOURCE_SHA="$source_sha"
export FAKE_WORKFLOW_ARGS="$temporary/workflow-args"
export FAKE_WATCH_MARKER="$temporary/watched"
GITHUB_OUTPUT="$dispatch_output" \
GITHUB_REPOSITORY=example/maestro \
SOURCE_SHA="$source_sha" \
GITHUB_SHA="$source_sha" \
  "$MAESTRO_CI_RELEASE_MANAGER" dispatch
grep -Fxq 'run_id=314' "$dispatch_output"
if grep -q '^restarted=' "$dispatch_output"; then
  printf 'Dispatch unexpectedly restarted the release.\n' >&2; exit 1
fi
grep -Fq -- '-f release_candidate=true' "$FAKE_WORKFLOW_ARGS"

# A VERSION merge requires a new caller source identity before synchronous CI.
rm "$FAKE_WATCH_MARKER" "$FAKE_DISPATCH_MARKER" "$FAKE_WORKFLOW_ARGS"
: >"$dispatch_output"
GITHUB_OUTPUT="$dispatch_output" GITHUB_REPOSITORY=example/maestro SOURCE_SHA="$source_sha" \
  GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa REQUESTED_BUMP=major \
  "$MAESTRO_CI_RELEASE_MANAGER" dispatch
grep -Fxq 'restarted=true' "$dispatch_output"
if grep -q '^run_id=' "$dispatch_output"; then
  printf 'Restart unexpectedly dispatched candidate CI.\n' >&2; exit 1
fi
grep -Fq -- 'workflow run release.yml --ref main -f bump=major -f event_continuation=false' "$FAKE_WORKFLOW_ARGS"
[[ ! -e "$FAKE_WATCH_MARKER" ]]

# Event mode must return after dispatch, never spend a runner watching CI.
rm "$FAKE_DISPATCH_MARKER" "$FAKE_WORKFLOW_ARGS"
: >"$dispatch_output"
GITHUB_OUTPUT="$dispatch_output" GITHUB_REPOSITORY=example/maestro SOURCE_SHA="$source_sha" \
  GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  EVENT_CONTINUATION=true MAESTRO_RELEASE_CONTINUATION_ENABLED=true GITHUB_RUN_ID=123 \
  "$MAESTRO_CI_RELEASE_MANAGER" dispatch
[[ ! -e "$FAKE_WATCH_MARKER" ]]
if grep -q '^restarted=' "$dispatch_output"; then
  printf 'Dispatch unexpectedly restarted the release.\n' >&2; exit 1
fi
grep -Fq -- '-f release_request_id=123' "$FAKE_WORKFLOW_ARGS"
rm "$FAKE_DISPATCH_MARKER" "$FAKE_WORKFLOW_ARGS"
if GITHUB_OUTPUT="$dispatch_output" GITHUB_REPOSITORY=example/maestro SOURCE_SHA="$source_sha" \
  EVENT_CONTINUATION=true MAESTRO_RELEASE_CONTINUATION_ENABLED=false GITHUB_RUN_ID=123 \
  "$MAESTRO_CI_RELEASE_MANAGER" dispatch >/dev/null 2>&1; then
  printf 'Disabled event continuation unexpectedly dispatched CI.\n' >&2; exit 1
fi
[[ ! -e "$FAKE_DISPATCH_MARKER" ]]

printf 'Release asset fixture checks passed.\n'
