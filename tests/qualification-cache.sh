#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_CI_QUALIFICATION_CACHE:?must point to the packaged cache preflight}"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/maestro-qualification-cache.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin"
cat >"$temporary/bin/nix" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 10 && "$2 $3 $4" == '--option narinfo-cache-negative-ttl 0' &&
   "$5 $6 $7" == '--option narinfo-cache-positive-ttl 0' &&
   "${10}" == "$FIXTURE_OUTPUT" ]]
case "$1 $8" in 'path-info --store'|'copy --from') ;; *) exit 2 ;; esac
printf '%s %s\n' "$1" "$9" >>"$FIXTURE_CALLS"
case "$9" in
  https://xen-orchestra-ce.cachix.org)
    case "$FIXTURE_HIT" in
      upstream) exit 0 ;;
      corrupt-upstream|corrupt-both) [[ $1 == path-info ]] ;;
      *) exit 1 ;;
    esac ;;
  https://maestro.cachix.org)
    case "$FIXTURE_HIT" in
      mirror|corrupt-upstream) exit 0 ;;
      corrupt-both) [[ $1 == path-info ]] ;;
      *) exit 1 ;;
    esac ;;
  *) exit 2 ;;
esac
EOF
sed -i "1c#!${BASH}" "$temporary/bin/nix"
chmod +x "$temporary/bin/nix"
export MAESTRO_CI_PATH_PREFIX="$temporary/bin"
export FIXTURE_OUTPUT=/nix/store/pmy7arxjj9zdwzxgbh31i4b53cax82cs-xen-orchestra-ce-6.9.1
export FIXTURE_CALLS="$temporary/calls"
for FIXTURE_HIT in upstream mirror neither corrupt-upstream corrupt-both; do
  export FIXTURE_HIT
  : >"$FIXTURE_CALLS"
  status=0
  "$MAESTRO_CI_QUALIFICATION_CACHE" "$FIXTURE_OUTPUT" >"$temporary/log" 2>&1 || status=$?
  case "$FIXTURE_HIT" in
    upstream) [[ $status == 0 && $(wc -l <"$FIXTURE_CALLS") == 2 ]] ;;
    mirror) [[ $status == 0 && $(wc -l <"$FIXTURE_CALLS") == 3 ]] ;;
    neither) [[ $status == 1 && $(wc -l <"$FIXTURE_CALLS") == 2 ]] ;;
    corrupt-upstream) [[ $status == 0 && $(wc -l <"$FIXTURE_CALLS") == 4 ]] ;;
    corrupt-both) [[ $status == 1 && $(wc -l <"$FIXTURE_CALLS") == 4 ]] ;;
  esac
  [[ $(head -n 1 "$FIXTURE_CALLS") == 'path-info https://xen-orchestra-ce.cachix.org' ]]
done
for invalid in /tmp/xen-orchestra-ce-6.9.1 "$FIXTURE_OUTPUT/child" "${FIXTURE_OUTPUT/ce-/other-}" ''; do
  : >"$FIXTURE_CALLS"
  status=0
  "$MAESTRO_CI_QUALIFICATION_CACHE" "$invalid" >"$temporary/log" 2>&1 || status=$?
  [[ $status == 2 && ! -s "$FIXTURE_CALLS" ]]
done
printf 'Qualification cache fixtures passed.\n'
