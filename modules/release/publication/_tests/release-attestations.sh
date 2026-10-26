#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_CI_RELEASE_ATTESTATIONS:?}"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/runtime" "$temporary/release" "$temporary/candidate"
export GITHUB_REPOSITORY=example/maestro SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export RELEASE_TAG=v3.0.0 RUNNER_TEMP="$temporary/runtime" FIXTURE="$temporary"
export MAESTRO_CI_PATH_PREFIX="$temporary/bin"
printf 'qualified ISO\n' >"$RUNNER_TEMP/maestro-v3.0.0.iso"
(cd "$RUNNER_TEMP" && sha256sum maestro-v3.0.0.iso) >"$temporary/release/maestro-v3.0.0.iso.sha256"
printf '{"spdxVersion":"SPDX-2.3","packages":[]}\n' >"$temporary/candidate/maestro-system.spdx.json"
cat >"$temporary/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == attestation && $2 == verify && $3 == "$RUNNER_TEMP/maestro-v3.0.0.iso" ]]
shift 3
supplied=$*
for required in '--repo example/maestro' \
  '--signer-workflow example/maestro/.github/workflows/release.yml' \
  '--source-ref refs/heads/main' \
  '--source-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  '--signer-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  '--deny-self-hosted-runners' '--format json' '--predicate-type'; do
  [[ $supplied == *"$required"* ]]
done
predicate=
while [[ $# -gt 0 ]]; do
  case $1 in
    --repo) [[ $2 == example/maestro ]]; shift 2 ;;
    --signer-workflow) [[ $2 == example/maestro/.github/workflows/release.yml ]]; shift 2 ;;
    --source-ref) [[ $2 == refs/heads/main ]]; shift 2 ;;
    --source-digest|--signer-digest) [[ $2 == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]]; shift 2 ;;
    --deny-self-hosted-runners) shift ;;
    --format) [[ $2 == json ]]; shift 2 ;;
    --predicate-type) predicate=$2; shift 2 ;;
    *) exit 2 ;;
  esac
done
printf '%s\n' "$predicate" >>"$FIXTURE/calls"
case ${FAILURE_MODE:-} in
  source|signer|untrusted) exit 1 ;;
  malformed) printf 'invalid JSON'; exit 0 ;;
  empty) printf '[]'; exit 0 ;;
esac
digest=$(sha256sum "$RUNNER_TEMP/maestro-v3.0.0.iso"); digest=${digest%% *}
name=maestro-v3.0.0.iso
[[ ${FAILURE_MODE:-} != subject ]] || name=unrelated.iso
[[ ${FAILURE_MODE:-} != digest ]] || digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
jq -n --arg type "$predicate" --arg digest "$digest" --arg name "$name" \
  --arg mode "${FAILURE_MODE:-}" --slurpfile sbom "$FIXTURE/candidate/maestro-system.spdx.json" '
  [{verificationResult:{statement:{predicateType:$type,
    subject:[{name:$name,digest:{sha256:$digest}}],
    predicate:(if $type == "https://spdx.dev/Document/v2.3" then
      (if $mode == "sbom" then {spdxVersion:"SPDX-2.3",packages:[{SPDXID:"wrong"}]} else $sbom[0] end)
      else {} end)}}}]'
EOF
sed -i "1c#!$BASH" "$temporary/bin/gh"
chmod +x "$temporary/bin/gh"
cd "$temporary"
"$MAESTRO_CI_RELEASE_ATTESTATIONS"
[[ $(wc -l <calls) == 2 ]]
for mode in source signer untrusted malformed empty subject digest sbom; do
  if FAILURE_MODE="$mode" "$MAESTRO_CI_RELEASE_ATTESTATIONS" >/dev/null 2>&1; then
    echo "Final release attestation gate accepted $mode drift" >&2
    exit 1
  fi
done
before=$(wc -l <calls)
printf 'changed ISO\n' >>"$RUNNER_TEMP/maestro-v3.0.0.iso"
if "$MAESTRO_CI_RELEASE_ATTESTATIONS" >/dev/null 2>&1; then
  echo 'Final release gate accepted a changed ISO' >&2; exit 1
fi
[[ $(wc -l <calls) == "$before" ]]
echo 'Final release provenance, source/signer, digest and SPDX fixtures passed.'
