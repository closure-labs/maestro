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
command=${0##*/}
[[ ${!#} == "$FIXTURE_OUTPUT" ]]
case "$command $1" in
  'nix path-info') operation=advertise; shift ;;
  'nix-store --realise') operation=realise; shift ;;
  'nix store') [[ $2 == verify ]]; operation=verify; shift 2 ;;
  *) exit 2 ;;
esac
# Reject missing/altered safeguards, unexpected caches, derivations or builders.
[[ $1 == --option && $2 == narinfo-cache-negative-ttl && $3 == 0 ]]; shift 3
[[ $1 == --option && $2 == narinfo-cache-positive-ttl && $3 == 0 ]]; shift 3
[[ $1 == --option && $2 == substituters && $3 == 'https://cache.nixos.org https://xen-orchestra-ce.cachix.org https://maestro.cachix.org' ]]; shift 3
[[ $1 == --option && $2 == trusted-public-keys && $3 == 'cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E= maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0=' ]]; shift 3
for pair in 'require-sigs true' 'substitute true' 'max-jobs 0' 'builders ' 'fallback false'; do
  [[ $1 == --option && "$2 $3" == "$pair" ]]; shift 3
done
case "$operation" in
  advertise)
    [[ $# == 3 && $1 == --store ]]
    printf 'advertise %s\n' "$2" >>"$FIXTURE_CALLS"
    case "$2:$FIXTURE_HIT" in
      https://xen-orchestra-ce.cachix.org:upstream) exit 0 ;;
      https://maestro.cachix.org:neither) exit 1 ;;
      https://maestro.cachix.org:*) exit 0 ;;
      *) exit 1 ;;
    esac ;;
  realise)
    [[ $# == 1 ]]
    echo realise >>"$FIXTURE_CALLS"
    # Model a closure split across official Bash, XO Node and mirrored XO root.
    # No individual source supports this fixture; only the checked union does.
    [[ $FIXTURE_HIT != missing-dependency && $FIXTURE_HIT != corrupt-download ]] ;;
  verify)
    [[ $# == 10 && "$1 $2 $3" == '--recursive --sigs-needed 1' &&
       "$4 $5" == '--substituter https://cache.nixos.org' &&
       "$6 $7" == '--substituter https://xen-orchestra-ce.cachix.org' &&
       "$8 $9" == '--substituter https://maestro.cachix.org' ]]
    echo verify >>"$FIXTURE_CALLS"
    [[ $FIXTURE_HIT != unsigned-warm && $FIXTURE_HIT != corrupt-warm ]] ;;
esac
EOF
sed -i "1c#!${BASH}" "$temporary/bin/nix"
chmod +x "$temporary/bin/nix"
ln -s nix "$temporary/bin/nix-store"
export MAESTRO_CI_PATH_PREFIX="$temporary/bin"
export FIXTURE_OUTPUT=/nix/store/pmy7arxjj9zdwzxgbh31i4b53cax82cs-xen-orchestra-ce-6.9.1
export FIXTURE_CALLS="$temporary/calls"
for FIXTURE_HIT in upstream mirror neither missing-dependency corrupt-download unsigned-warm corrupt-warm; do
  export FIXTURE_HIT
  : >"$FIXTURE_CALLS"
  status=0
  "$MAESTRO_CI_QUALIFICATION_CACHE" "$FIXTURE_OUTPUT" >"$temporary/log" 2>&1 || status=$?
  case "$FIXTURE_HIT" in
    upstream) [[ $status == 0 && $(wc -l <"$FIXTURE_CALLS") == 3 ]] ;;
    mirror) [[ $status == 0 && $(wc -l <"$FIXTURE_CALLS") == 4 ]] ;;
    neither) [[ $status == 1 && $(wc -l <"$FIXTURE_CALLS") == 2 ]] ;;
    missing-dependency|corrupt-download) [[ $status == 1 && $(wc -l <"$FIXTURE_CALLS") == 3 ]] ;;
    unsigned-warm|corrupt-warm) [[ $status == 1 && $(wc -l <"$FIXTURE_CALLS") == 4 ]] ;;
  esac
  [[ $(head -n 1 "$FIXTURE_CALLS") == 'advertise https://xen-orchestra-ce.cachix.org' ]]
done
for invalid in /tmp/xen-orchestra-ce-6.9.1 "$FIXTURE_OUTPUT/child" "${FIXTURE_OUTPUT/ce-/other-}" ''; do
  : >"$FIXTURE_CALLS"
  status=0
  "$MAESTRO_CI_QUALIFICATION_CACHE" "$invalid" >"$temporary/log" 2>&1 || status=$?
  [[ $status == 2 && ! -s "$FIXTURE_CALLS" ]]
done
printf 'Qualification cache fixtures passed.\n'
