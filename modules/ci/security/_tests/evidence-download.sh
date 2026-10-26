#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_CI_DOWNLOAD_INSTALLER:?}"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/inventory/result-installer/iso"
export MAESTRO_CI_PATH_PREFIX="$temporary/bin"
export GITHUB_REPOSITORY=example/maestro FAKE_EVIDENCE_FIXTURE="$temporary"
sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export FAKE_EVIDENCE_SHA="$sha"
inventory=$temporary/inventory
printf 'ISO\n' >"$inventory/result-installer/iso/maestro-installer.iso"
for component in maestro-system xen-orchestra-supply; do
  printf '{"spdxVersion":"SPDX-2.3"}\n' >"$inventory/$component.spdx.json"
  printf '{"bomFormat":"CycloneDX","components":[]}\n' >"$inventory/$component.cdx.json"
done
printf '{"schemaVersion":1}\n' >"$inventory/xen-orchestra-supply.assertion.json"
# The newest pointer selects assembled artifact 7; original evidence run 6
# must never be mistaken for the complete assembled evidence artifact.
jq -n --arg sha "$sha" '{schema_version:5,mode:"qualify-media-reuse-evidence",media_input:("a"*64),evidence_input:("b"*64),source_commit:$sha,artifact_source_commit:$sha,media_source_commit:$sha,producer_event:"push",artifact_run_id:7,media_run_id:7,evidence_run_id:6}' >"$inventory/maestro-qualification-state.json"
cp "$inventory/maestro-qualification-state.json" "$temporary/pointer.json"
(
  cd "$inventory"
  for file in result-installer/iso/maestro-installer.iso maestro-system.spdx.json maestro-system.cdx.json xen-orchestra-supply.assertion.json xen-orchestra-supply.spdx.json xen-orchestra-supply.cdx.json; do
    sha256sum "$file" >"${file##*/}.sha256"
  done
)
cp "$inventory/maestro-system.spdx.json" "$temporary/predicate.json"
(cd "$inventory" && sha256sum result-installer/iso/maestro-installer.iso ./*.json) >"$temporary/signed-digests"
sha256sum "$temporary/pointer.json" >>"$temporary/signed-digests"
cat >"$temporary/bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
fixture=${FAKE_EVIDENCE_FIXTURE:?}
sha=${FAKE_EVIDENCE_SHA:?}
if [[ $1 == api ]]; then
  case $2 in
    */actions/runs/*)
      run_id=${2##*/}
      jq -n --arg sha "$sha" --argjson id "$run_id" --arg event "${FAKE_EVIDENCE_EVENT:-push}" \
        '{id:$id,status:"completed",conclusion:"success",head_repository:{full_name:"example/maestro"},head_branch:"main",head_sha:$sha,path:".github/workflows/ci.yml",event:$event}'
      ;;
    */branches/main) jq -n --arg sha "$sha" '{protected:true,commit:{sha:$sha}}' ;;
    */compare/*) jq -n --arg sha "$sha" '{merge_base_commit:{sha:$sha}}' ;;
    *) exit 1 ;;
  esac
elif [[ "$1 $2" == 'attestation verify' ]]; then
  [[ $* == *'--source-ref refs/heads/main'* && $* == *'--deny-self-hosted-runners'* ]]
  [[ $* == *'--signer-workflow example/maestro/.github/workflows/ci.yml'* ]]
  [[ $* == *"--source-digest $sha"* && $* == *"--signer-digest $sha"* ]]
  actual=$(sha256sum "$3")
  grep -Fq "${actual%% *} " "$fixture/signed-digests"
  if [[ $* == *'--format json'* ]]; then
    jq -n --slurpfile predicate "$fixture/predicate.json" '[{verificationResult:{statement:{predicate:$predicate[0]}}}]'
  fi
elif [[ "$1 $2" == 'run list' ]]; then
  printf '8\n'
elif [[ "$1 $2" == 'run download' ]]; then
  run_id=$3
  name='' destination=''
  while [[ $# -gt 0 ]]; do
    case $1 in --name) name=$2; shift 2 ;; --dir) destination=$2; shift 2 ;; *) shift ;; esac
  done
  printf '%s %s\n' "$run_id" "$name" >>"$fixture/downloads"
  case $name in
    maestro-qualification-state)
      [[ $run_id == 8 ]]
      cp "$fixture/pointer.json" "$destination/maestro-qualification-state.json"
      ;;
    maestro-installer)
      [[ $run_id == 7 ]]
      cp -R "$fixture/inventory/." "$destination/"
      ;;
    maestro-evidence)
      [[ $run_id == 7 ]]
      cp "$fixture/inventory/"*.json "$fixture/inventory/"*.json.sha256 "$destination/"
      ;;
    *) exit 1 ;;
  esac
else exit 1; fi
GH
sed -i "1c#!${BASH}" "$temporary/bin/gh"
chmod +x "$temporary/bin/gh"
reject() {
  if "$@" >"$temporary/rejected.log" 2>&1; then
    printf 'Accepted invalid evidence input: %s\n' "$*" >&2
    exit 1
  fi
  [[ ! -e $temporary/rejected ]]
}
"$MAESTRO_CI_DOWNLOAD_INSTALLER" "$temporary/evidence" evidence
[[ ! -e $temporary/evidence/result-installer ]]
cmp "$temporary/pointer.json" "$temporary/evidence/selected-state.json"
grep -Fxq '7 maestro-evidence' "$temporary/downloads"
[[ $(wc -l <"$temporary/downloads") == 2 ]]
# Full mode remains the default and still checks the media SBOM predicate.
"$MAESTRO_CI_DOWNLOAD_INSTALLER" "$temporary/full"
cmp "$inventory/result-installer/iso/maestro-installer.iso" "$temporary/full/result-installer/iso/maestro-installer.iso"
grep -Fxq '7 maestro-installer' "$temporary/downloads"
printf '{"spdxVersion":"SPDX-2.3","tampered":true}\n' >"$temporary/predicate.json"
reject "$MAESTRO_CI_DOWNLOAD_INSTALLER" "$temporary/rejected"
cp "$inventory/maestro-system.spdx.json" "$temporary/predicate.json"
# A PR-produced run cannot supply trusted signed evidence.
FAKE_EVIDENCE_EVENT=pull_request reject "$MAESTRO_CI_DOWNLOAD_INSTALLER" "$temporary/rejected" evidence
# Checksum-consistent tampering still fails the evidence attestation.
cp "$inventory/maestro-system.cdx.json" "$temporary/original.cdx.json"
cp "$inventory/maestro-system.cdx.json.sha256" "$temporary/original.cdx.sha256"
printf '{"bomFormat":"CycloneDX","components":[{"name":"tampered"}]}\n' >"$inventory/maestro-system.cdx.json"
(cd "$inventory" && sha256sum maestro-system.cdx.json >maestro-system.cdx.json.sha256)
reject "$MAESTRO_CI_DOWNLOAD_INSTALLER" "$temporary/rejected" evidence
cp "$temporary/original.cdx.json" "$inventory/maestro-system.cdx.json"
cp "$temporary/original.cdx.sha256" "$inventory/maestro-system.cdx.json.sha256"
# Even a separately signed pointer cannot select different input identities.
jq '.evidence_input=("c"*64)' "$inventory/maestro-qualification-state.json" >"$temporary/pointer.json"
sha256sum "$temporary/pointer.json" >>"$temporary/signed-digests"
reject "$MAESTRO_CI_DOWNLOAD_INSTALLER" "$temporary/rejected" evidence
reject "$MAESTRO_CI_DOWNLOAD_INSTALLER" "$temporary/rejected" invalid
printf 'Evidence download fixtures passed.\n'
