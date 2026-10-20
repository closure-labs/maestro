#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
: "${MAESTRO_SPDX_SCHEMA:?MAESTRO_SPDX_SCHEMA must point to the pinned SPDX schema}"
: "${QUALIFICATION_MODE:?QUALIFICATION_MODE must be a supported qualification mode}"

repo_root=${MAESTRO_SYSTEM_ROOT:-}
if [[ -z "$repo_root" ]]; then
  repo_root=$(git rev-parse --show-toplevel)
fi
cd "$repo_root"
runner_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
media_manifest=
manifest=
sbom_work=
cleanup() {
  [[ -z "$sbom_work" ]] || rm -rf -- "$sbom_work"
  [[ -z "$manifest" ]] || rm -f -- "$manifest"
  [[ -z "$media_manifest" ]] || rm -f -- "$media_manifest"
}
trap cleanup EXIT

# Check the hosted metadata interface and approved publications before building.
maestro-ci-security-inventory-preflight
nix config show substituters
nix config show trusted-public-keys
determinate_out=$(nix eval --accept-flake-config --raw .#nixosConfigurations.maestro.config.nix.package.upstream.outPath)
nix path-info --store https://install.determinate.systems "$determinate_out"
xo_out=$(nix eval --accept-flake-config --raw .#packages.x86_64-linux.xen-orchestra-ce.outPath)
maestro-ci-qualification-cache "$xo_out"

case "$QUALIFICATION_MODE" in
  qualify-media|qualify-media-reuse-evidence)
    media_manifest=$(mktemp "${runner_temp}/maestro-media-plan.XXXXXX")
    flake-plan-runner --flake "path:$repo_root" --plan lib.ciPlans.x86_64-linux.media --manifest "$media_manifest"
    ;;
  refresh-evidence)
    : "${GH_TOKEN:?GH_TOKEN is required to verify reused media}"
    reused_sha=$(jq -er .artifact_source_commit reused-media/maestro-qualification-state.json)
    maestro-ci-verify-inventory reused-media "$reused_sha"
    [[ $(jq -er .media_input reused-media/maestro-qualification-state.json) == "${EXPECTED_MEDIA_INPUT:?}" ]]
    reused_installer=reused-media/result-installer
    [[ -f "$reused_installer/iso/maestro-installer.iso" ]]
    mv "$reused_installer" result-installer
    ;;
  *)
    printf 'Unsupported qualification mode: %s\n' "$QUALIFICATION_MODE" >&2
    exit 1
    ;;
esac

manifest=$(mktemp "${runner_temp}/maestro-plan.XXXXXX")
flake-plan-runner --flake "path:$repo_root" --plan lib.ciPlans.x86_64-linux.evidence --manifest "$manifest"
# Native scans open every distributed output on this same qualification runner.
nix build --accept-flake-config --no-link "path:$repo_root#packages.x86_64-linux.distribution-inventory"

sbomnix_out=$(jq -er '.results[] | select(.name == "sbomnix") | .outputs | select(length == 1) | .[0]' "$manifest")
manifest_xo_out=$(jq -er '.results[] | select(.name == "xen-orchestra-ce") | .outputs | select(length == 1) | .[0]' "$manifest")
[[ "$manifest_xo_out" == "$xo_out" ]]
xo_supply_out=$(jq -er '.results[] | select(.name == "xen-orchestra-supply-protector") | .outputs | select(length == 1) | .[0]' "$manifest")

if [[ "$QUALIFICATION_MODE" == qualify-media-reuse-evidence ]]; then
  : "${EXPECTED_EVIDENCE_INPUT:?EXPECTED_EVIDENCE_INPUT must identify reused evidence}"
  : "${EXPECTED_EVIDENCE_RUN_ID:?EXPECTED_EVIDENCE_RUN_ID must identify reused evidence}"
  maestro-ci-verify-state reused-evidence/maestro-qualification-state.json "$EXPECTED_EVIDENCE_RUN_ID"
  maestro-ci-verify-inventory reused-evidence "$(jq -er .artifact_source_commit reused-evidence/maestro-qualification-state.json)" evidence
  jq -e --arg evidence_input "$EXPECTED_EVIDENCE_INPUT" --argjson evidence_run_id "$EXPECTED_EVIDENCE_RUN_ID" '
      .schema_version == 5 and
      .evidence_input == $evidence_input and
      .evidence_run_id == $evidence_run_id
    ' reused-evidence/maestro-qualification-state.json >/dev/null
  for evidence_file in maestro-system.spdx.json maestro-system.spdx.json.sha256 maestro-system.cdx.json maestro-system.cdx.json.sha256 xen-orchestra-supply.assertion.json xen-orchestra-supply.assertion.json.sha256 xen-orchestra-supply.spdx.json xen-orchestra-supply.spdx.json.sha256 xen-orchestra-supply.cdx.json xen-orchestra-supply.cdx.json.sha256; do
    install -m 0644 "reused-evidence/$evidence_file" "$evidence_file"
  done
else
  (cd "$xo_supply_out" && sha256sum --check --strict SHA256SUMS)
  install -m 0644 "$xo_supply_out/assertion.json" xen-orchestra-supply.assertion.json
  install -m 0644 "$xo_supply_out/xen-orchestra.spdx.json" xen-orchestra-supply.spdx.json
  install -m 0644 "$xo_supply_out/xen-orchestra.cdx.json" xen-orchestra-supply.cdx.json

  sbom_work=$(mktemp -d "${runner_temp}/maestro-sbom.XXXXXX")
  (
    cd "$sbom_work"
    "$sbomnix_out/bin/sbomnix" "path:${repo_root}#packages.x86_64-linux.distribution-inventory"
  )
  mv "$sbom_work/sbom.spdx.json" maestro-system.spdx.json
  mv "$sbom_work/sbom.cdx.json" maestro-system.cdx.json
  maestro-ci-security-inventory maestro-system.cdx.json xen-orchestra-supply.cdx.json

  xo_version=$(jq -er .subject.version xen-orchestra-supply.assertion.json)
  xo_document_namespace=$(jq -er .documentNamespace xen-orchestra-supply.spdx.json)
  xo_document_root=$(jq -er '
    [.relationships[] |
      select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES") |
      .relatedSpdxElement] |
    select(length == 1) | .[0]
  ' xen-orchestra-supply.spdx.json)
  appliance_xo_element=$(jq -er --arg version "$xo_version" '
    [.packages[] |
      select(.name == "xen-orchestra-ce" and .versionInfo == $version) |
      .SPDXID] |
    select(length == 1) | .[0]
  ' maestro-system.spdx.json)

  jq -S --arg appliance_xo_element "$appliance_xo_element" --arg namespace "$xo_document_namespace" --arg root "$xo_document_root" --arg sha256 "$(jq -er .documents.spdx.sha256 xen-orchestra-supply.assertion.json)" '
    .externalDocumentRefs = ((.externalDocumentRefs // []) + [{
      externalDocumentId: "DocumentRef-XOSupply",
      spdxDocument: $namespace,
      checksum: {algorithm: "SHA256", checksumValue: $sha256}
    }]) |
    .relationships += [{
      spdxElementId: $appliance_xo_element,
      relationshipType: "DESCRIBED_BY",
      relatedSpdxElement: ("DocumentRef-XOSupply:" + $root)
    }]
  ' maestro-system.spdx.json >"$sbom_work/maestro-system.spdx.json"
  mv "$sbom_work/maestro-system.spdx.json" maestro-system.spdx.json

  sha256sum maestro-system.spdx.json >maestro-system.spdx.json.sha256
  sha256sum maestro-system.cdx.json >maestro-system.cdx.json.sha256
  sha256sum xen-orchestra-supply.assertion.json >xen-orchestra-supply.assertion.json.sha256
  sha256sum xen-orchestra-supply.spdx.json >xen-orchestra-supply.spdx.json.sha256
  sha256sum xen-orchestra-supply.cdx.json >xen-orchestra-supply.cdx.json.sha256
fi

(cd "$xo_supply_out" && sha256sum --check --strict SHA256SUMS)
nix-store --query --references "$xo_supply_out" | grep -Fx -- "$xo_out" >/dev/null
cache_url=https://xen-orchestra-ce.cachix.org
cache_key='xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E='
jq -e --arg cache_key "$cache_key" --arg cache_url "$cache_url" --arg xo_out "$xo_out" '
  .schemaVersion == 1 and
  .subject.name == "xen-orchestra-ce" and
  .subject.channel == "latest" and
  .subject.storePath == $xo_out and
  .distribution.substituter == $cache_url and
  .distribution.trustedPublicKey == $cache_key
' xen-orchestra-supply.assertion.json >/dev/null

asserted_spdx_sha=$(jq -er .documents.spdx.sha256 xen-orchestra-supply.assertion.json)
asserted_cdx_sha=$(jq -er .documents.cyclonedx.sha256 xen-orchestra-supply.assertion.json)
[[ "$(sha256sum xen-orchestra-supply.spdx.json | cut -d' ' -f1)" == "$asserted_spdx_sha" ]]
[[ "$(sha256sum xen-orchestra-supply.cdx.json | cut -d' ' -f1)" == "$asserted_cdx_sha" ]]

xo_version=$(jq -er .subject.version xen-orchestra-supply.assertion.json)
xo_document_root=$(jq -er '
  [.relationships[] |
    select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES") |
    .relatedSpdxElement] |
  select(length == 1) | .[0]
' xen-orchestra-supply.spdx.json)
appliance_xo_element=$(jq -er --arg version "$xo_version" '
  [.packages[] |
    select(.name == "xen-orchestra-ce" and .versionInfo == $version) |
    .SPDXID] |
  select(length == 1) | .[0]
' maestro-system.spdx.json)
jq -e --arg appliance_xo_element "$appliance_xo_element" --arg root "$xo_document_root" --arg sha256 "$asserted_spdx_sha" '
  any(.externalDocumentRefs[];
    .externalDocumentId == "DocumentRef-XOSupply" and
    .checksum.algorithm == "SHA256" and
    .checksum.checksumValue == $sha256) and
  any(.relationships[];
    .spdxElementId == $appliance_xo_element and
    .relationshipType == "DESCRIBED_BY" and
    .relatedSpdxElement == ("DocumentRef-XOSupply:" + $root))
' maestro-system.spdx.json >/dev/null

(
  sha256sum --check --strict maestro-system.spdx.json.sha256
  sha256sum --check --strict maestro-system.cdx.json.sha256
  sha256sum --check --strict xen-orchestra-supply.assertion.json.sha256
  sha256sum --check --strict xen-orchestra-supply.spdx.json.sha256
  sha256sum --check --strict xen-orchestra-supply.cdx.json.sha256
)
check-jsonschema --schemafile "$MAESTRO_SPDX_SCHEMA" maestro-system.spdx.json
jq -e '.bomFormat == "CycloneDX"' maestro-system.cdx.json >/dev/null

installer_iso=result-installer/iso/maestro-installer.iso
installer_budget_bytes=${MAESTRO_INSTALLER_ARTIFACT_BUDGET_BYTES:-3000000000}
installer_size_bytes=$(stat -c %s "$installer_iso")
if (( installer_size_bytes > installer_budget_bytes )); then
  printf 'Installer ISO is %s bytes, exceeding the %s-byte artifact budget\n' \
    "$installer_size_bytes" "$installer_budget_bytes" >&2
  exit 1
fi
printf 'Installer ISO size: %s bytes (budget: %s bytes)\n' \
  "$installer_size_bytes" "$installer_budget_bytes"
sha256sum result-installer/iso/maestro-installer.iso >maestro-installer.iso.sha256
