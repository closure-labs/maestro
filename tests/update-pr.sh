#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_CI_OPEN_UPDATE_PR:?must point to the packaged update publisher}"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/maestro-update-pr.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin"
export REAL_GIT
REAL_GIT=$(command -v git)

# Exercise real commits and lease-protected pushes against a local bare remote;
# never let the publisher's authenticated GitHub URL leave this fixture.
cat >"$temporary/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == 'remote set-url' ]]; then
  [[ "$3" == origin && "$4" == 'https://x-access-token:fixture@github.com/example/maestro.git' ]]
  exec "$REAL_GIT" remote set-url origin "$FIXTURE_REMOTE"
fi
exec "$REAL_GIT" "$@"
EOF
cat >"$temporary/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FIXTURE_CALLS"
case "$1 $2" in
  'pr view')
    # Reproduce gh's successful lookup of a historical PR for a reused branch.
    printf '{"number":32,"state":"%s"}\n' "${FIXTURE_HISTORICAL_STATE:-MERGED}"
    ;;
  'pr list')
    [[ "$*" == *'--state open'* && "$*" == *'--base main'* &&
       "$*" == *'--head automation/weekly-flake-input-refresh'* &&
       "$*" == *'--repo example/maestro'* ]]
    [[ ${FIXTURE_LOOKUP_FAILURE:-false} != true ]] || exit 7
    printf '%s\n' "${FIXTURE_OPEN_PRS:-[]}"
    ;;
  'pr edit') [[ "$3" == 42 ]]; printf 'edit\n' >>"$FIXTURE_WRITES" ;;
  'pr create') printf 'create\n' >>"$FIXTURE_WRITES" ;;
  *) exit 1 ;;
esac
EOF
sed -i "1c#!${BASH}" "$temporary/bin/git" "$temporary/bin/gh"
chmod +x "$temporary/bin/git" "$temporary/bin/gh"

run_case() (
  local name=$1
  local expected=$2
  shift 2
  local work="$temporary/$name"
  export FIXTURE_REMOTE="$temporary/$name.git"
  export FIXTURE_CALLS="$temporary/$name.calls"
  export FIXTURE_WRITES="$temporary/$name.writes"
  "$REAL_GIT" init -q --bare "$FIXTURE_REMOTE"
  "$REAL_GIT" init -q -b main "$work"
  cd "$work"
  "$REAL_GIT" config user.email fixture@example.invalid
  "$REAL_GIT" config user.name Fixture
  printf 'old\n' >flake.lock
  "$REAL_GIT" add flake.lock
  "$REAL_GIT" commit -qm initial
  "$REAL_GIT" remote add origin "$FIXTURE_REMOTE"
  [[ "$name" == unchanged ]] || printf 'updated\n' >flake.lock
  local status=0
  env MAESTRO_CI_PATH_PREFIX="$temporary/bin" \
    GH_TOKEN=fixture GITHUB_REPOSITORY=example/maestro \
    UPDATE_BRANCH=automation/weekly-flake-input-refresh \
    UPDATE_TITLE='locks: refresh Nix and devenv inputs' UPDATE_BODY='Fixture update' \
    "$@" "$MAESTRO_CI_OPEN_UPDATE_PR" flake.lock >"$temporary/$name.log" 2>&1 || status=$?
  if [[ "$expected" == failure ]]; then
    [[ "$status" == 7 && ! -e "$FIXTURE_WRITES" ]]
  else
    [[ "$status" == 0 ]]
    if [[ "$expected" == none ]]; then
      [[ ! -e "$FIXTURE_CALLS" && ! -e "$FIXTURE_WRITES" ]]
    else
      [[ $(cat "$FIXTURE_WRITES") == "$expected" ]]
      [[ $("$REAL_GIT" show "$("$REAL_GIT" --git-dir="$FIXTURE_REMOTE" rev-parse refs/heads/automation/weekly-flake-input-refresh):flake.lock") == updated ]]
    fi
  fi
)

run_case merged create FIXTURE_HISTORICAL_STATE=MERGED
run_case closed create FIXTURE_HISTORICAL_STATE=CLOSED
run_case open edit 'FIXTURE_OPEN_PRS=[{"number":42,"headRepository":{"nameWithOwner":"example/maestro"}}]'
run_case fork create 'FIXTURE_OPEN_PRS=[{"number":99,"headRepository":{"nameWithOwner":"other/maestro"}}]'
run_case fork_and_open edit 'FIXTURE_OPEN_PRS=[{"number":99,"headRepository":{"nameWithOwner":"other/maestro"}},{"number":42,"headRepository":{"nameWithOwner":"example/maestro"}}]'
run_case outage failure FIXTURE_LOOKUP_FAILURE=true
run_case unchanged none
printf 'Update PR publication fixtures passed.\n'
