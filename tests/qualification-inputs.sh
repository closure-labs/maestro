#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
: "${MAESTRO_CI_QUALIFICATION_INPUTS:?MAESTRO_CI_QUALIFICATION_INPUTS must point to the packaged input resolver}"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/maestro-qualification-inputs.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/source"

cat >"$temporary/bin/nix" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${FAKE_QUALIFICATION_GRAPH:?}"
EOF
sed -i "1c#!${BASH}" "$temporary/bin/nix"
chmod +x "$temporary/bin/nix"

resolve() {
  MAESTRO_CI_PATH_PREFIX="$temporary/bin" \
    MAESTRO_SYSTEM_ROOT="$temporary/source" \
    FAKE_QUALIFICATION_GRAPH="$1" \
    "$MAESTRO_CI_QUALIFICATION_INPUTS"
}

baseline=$(resolve '{"media":{"installer":"/nix/store/media-a","bootPolicy":"boot-a"},"evidence":{"toplevel":"/nix/store/system-a","sbomnix":"/nix/store/sbom-a"}}')
jq -e '
  .schema_version == 1 and
  (.media_input | test("^[0-9a-f]{64}$")) and
  (.evidence_input | test("^[0-9a-f]{64}$"))
' <<<"$baseline" >/dev/null

reordered=$(resolve '{"evidence":{"sbomnix":"/nix/store/sbom-a","toplevel":"/nix/store/system-a"},"media":{"bootPolicy":"boot-a","installer":"/nix/store/media-a"}}')
[[ "$reordered" == "$baseline" ]]

evidence_change=$(resolve '{"media":{"installer":"/nix/store/media-a","bootPolicy":"boot-a"},"evidence":{"toplevel":"/nix/store/system-a","sbomnix":"/nix/store/sbom-b"}}')
[[ $(jq -r .media_input <<<"$evidence_change") == $(jq -r .media_input <<<"$baseline") ]]
[[ $(jq -r .evidence_input <<<"$evidence_change") != $(jq -r .evidence_input <<<"$baseline") ]]

media_change=$(resolve '{"media":{"installer":"/nix/store/media-b","bootPolicy":"boot-a"},"evidence":{"toplevel":"/nix/store/system-a","sbomnix":"/nix/store/sbom-a"}}')
[[ $(jq -r .media_input <<<"$media_change") != $(jq -r .media_input <<<"$baseline") ]]
[[ $(jq -r .evidence_input <<<"$media_change") == $(jq -r .evidence_input <<<"$baseline") ]]

# The embedded appliance is an input to both media and evidence. Host policy
# changes must invalidate the ISO, even when installer sources are unchanged.
seed_baseline=$(resolve '{"media":{"source":"same","dependencies":{"applianceToplevel":"/nix/store/system-a"}},"evidence":{"toplevel":"/nix/store/system-a"}}')
seed_change=$(resolve '{"media":{"source":"same","dependencies":{"applianceToplevel":"/nix/store/system-b"}},"evidence":{"toplevel":"/nix/store/system-b"}}')
[[ $(jq -r .media_input <<<"$seed_change") != $(jq -r .media_input <<<"$seed_baseline") ]]
[[ $(jq -r .evidence_input <<<"$seed_change") != $(jq -r .evidence_input <<<"$seed_baseline") ]]

# Only evaluated media and boot acceptance affect the media identity. Evidence
# tool changes can refresh scans without invalidating already booted ISO bytes.
exact_baseline=$(resolve '{"media":{"dependencies":{"installerIso":"/nix/store/iso-a","applianceToplevel":"/nix/store/system-a"},"bootPolicy":"boot-a"},"evidence":{"distribution":"/nix/store/tools-a"}}')
exact_tools=$(resolve '{"media":{"dependencies":{"installerIso":"/nix/store/iso-a","applianceToplevel":"/nix/store/system-a"},"bootPolicy":"boot-a"},"evidence":{"distribution":"/nix/store/tools-b"}}')
[[ $(jq -r .media_input <<<"$exact_baseline") == $(jq -r .media_input <<<"$exact_tools") ]]
for media in \
  '{"dependencies":{"installerIso":"/nix/store/iso-b","applianceToplevel":"/nix/store/system-a"},"bootPolicy":"boot-a"}' \
  '{"dependencies":{"installerIso":"/nix/store/iso-a","applianceToplevel":"/nix/store/system-a"},"bootPolicy":"boot-b"}'; do
  changed=$(resolve "{\"media\":$media,\"evidence\":{\"distribution\":\"/nix/store/tools-a\"}}")
  [[ $(jq -r .media_input <<<"$changed") != $(jq -r .media_input <<<"$exact_baseline") ]]
done

if resolve '{"media":null,"evidence":{}}' >/dev/null 2>&1; then
  printf 'Qualification input resolver accepted an invalid Nix graph.\n' >&2
  exit 1
fi

printf 'Focused qualification input checks passed.\n'
