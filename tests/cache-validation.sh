#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_CI_CACHE_VALIDATION:?}"
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin"
export MAESTRO_CI_PATH_PREFIX="$temporary/bin"
export CACHIX_CACHE_NAME=nixoa FAKE_CACHE_FIXTURE="$temporary"
export GITHUB_ACTIONS=false
# Two roots occur throughout all validation targets to prove deduplication
# without relying on fixture-only subsets of the actual repository plan.
first=/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-validation-one
second=/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-validation-two
jq -n --slurpfile contract "$root/nix/ci-plans.json" --arg first "$first" --arg second "$second" '
  {schemaVersion:2,plan:"maestro-validation",flake:"path:/fixture",failureCount:0,
   targetCount:($contract[0].validation.targets | length),
   results:[$contract[0].validation.targets[] |
     {name,attribute,status:"success",outputs:[$second,$first,$first]}]}
' >"$temporary/valid.json"
cat >"$temporary/bin/nix" <<'NIX'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == path-info ]]
shift
printf '%s\n' "$@" >"${FAKE_CACHE_FIXTURE:?}/queried"
[[ ${FAKE_CACHE_MISSING:-false} != true ]]
NIX
cat >"$temporary/bin/cachix" <<'CACHIX'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2" == 'push nixoa' ]]
cat >"${FAKE_CACHE_FIXTURE:?}/published"
CACHIX
sed -i "1c#!${BASH}" "$temporary/bin/nix" "$temporary/bin/cachix"
chmod +x "$temporary/bin/nix" "$temporary/bin/cachix"
"$MAESTRO_CI_CACHE_VALIDATION" "$temporary/valid.json"
printf '%s\n' "$first" "$second" >"$temporary/expected"
cmp "$temporary/expected" "$temporary/published"
cmp "$temporary/expected" "$temporary/queried"
reject() {
  rm -f "$temporary/published" "$temporary/queried"
  if "$@" >"$temporary/rejected.log" 2>&1; then
    printf 'Accepted invalid validation publication: %s\n' "$*" >&2
    exit 1
  fi
  [[ ! -e $temporary/published ]]
}
for alteration in \
  '.schemaVersion=1' \
  '.plan="maestro-publish"' \
  '.failureCount=1' \
  '.results[0].status="failure"' \
  '.results[0].outputs=[]' \
  '.results[0].outputs=["/etc/passwd"]' \
  '.results[0].outputs=["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root/child"]' \
  '.results[0].outputs=["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root\nextra"]' \
  '.results[0].outputs=["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root\n"]' \
  '.results[0].attribute="packages.x86_64-linux.unrelated"' \
  '.results[0].name="unexpected"' \
  '.results=.results[1:] | .targetCount=(.results | length)' \
  '.results[0]=.results[1]' \
  '.extra=true'; do
  jq "$alteration" "$temporary/valid.json" >"$temporary/invalid.json"
  reject "$MAESTRO_CI_CACHE_VALIDATION" "$temporary/invalid.json"
  [[ ! -e $temporary/queried ]]
done
printf '{malformed\n' >"$temporary/invalid.json"
reject "$MAESTRO_CI_CACHE_VALIDATION" "$temporary/invalid.json"
[[ ! -e $temporary/queried ]]
FAKE_CACHE_MISSING=true reject "$MAESTRO_CI_CACHE_VALIDATION" "$temporary/valid.json"
[[ -e $temporary/queried ]]
# Hosted execution is refused before even querying paths or inspecting a file.
GITHUB_ACTIONS=true reject "$MAESTRO_CI_CACHE_VALIDATION" "$temporary/nonexistent.json"
[[ ! -e $temporary/queried ]]
CACHIX_CACHE_NAME='' reject "$MAESTRO_CI_CACHE_VALIDATION" "$temporary/valid.json"
[[ ! -e $temporary/queried ]]
CACHIX_CACHE_NAME=--invalid reject "$MAESTRO_CI_CACHE_VALIDATION" "$temporary/valid.json"
[[ ! -e $temporary/queried ]]
# The audit preserves its existing invocation and forwards an optional output
# manifest, including paths containing spaces, to the actual plan runner.
cat >"$temporary/bin/git" <<'GIT'
#!/usr/bin/env bash
exit 1
GIT
cat >"$temporary/bin/nix" <<'NIX'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2" == 'flake check' && $* == *'--no-write-lock-file'* ]]
NIX
cat >"$temporary/bin/maestro-ci-security-inventory-preflight" <<'PREFLIGHT'
#!/usr/bin/env bash
exit 0
PREFLIGHT
cat >"$temporary/bin/flake-plan-runner" <<'RUNNER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"${FAKE_CACHE_FIXTURE:?}/runner-args"
RUNNER
sed -i "1c#!${BASH}" "$temporary/bin/git" "$temporary/bin/nix" \
  "$temporary/bin/maestro-ci-security-inventory-preflight" "$temporary/bin/flake-plan-runner"
chmod +x "$temporary/bin/"*
(
  unset MAESTRO_CI_AUDIT_MANIFEST
  PATH="$temporary/bin:$PATH" MAESTRO_SYSTEM_ROOT="$temporary" \
    bash "$root/nix/automation/repository-audit.sh" --no-write-lock-file
)
printf '%s\n' --flake "path:$temporary" --plan lib.ciPlans.x86_64-linux.validation >"$temporary/expected-args"
cmp "$temporary/expected-args" "$temporary/runner-args"
PATH="$temporary/bin:$PATH" MAESTRO_SYSTEM_ROOT="$temporary" \
  MAESTRO_CI_AUDIT_MANIFEST="$temporary/manifest with spaces.json" \
  bash "$root/nix/automation/repository-audit.sh" --no-write-lock-file
printf '%s\n' --manifest "$temporary/manifest with spaces.json" >>"$temporary/expected-args"
cmp "$temporary/expected-args" "$temporary/runner-args"
printf 'Validation cache fixtures passed.\n'
