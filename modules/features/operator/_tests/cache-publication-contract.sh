#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=${1:?source root required}
relative=modules/release/publication/_source/publish.sh
candidate=modules/ci/authority/_source/decision-candidate.py
restore=modules/ci/authority/_source/distribution-restore.py
verifier=modules/ci/authority/_source/decisions/cache_publication.py
policy=modules/ci/authority/_source/decision-policy.json

has_text() {
  grep -F -- "$3" "$1/$2" | grep -v '^[[:space:]]*#' >/dev/null
}

check_contract() {
  local source_root=$1
  jq -e '.cachePublication == {
      schema: 1, scope: "selected-project-closures",
      roots: ["maestro-menu", "maestroctl", "deploy-template", "sbomnix"]
    }' "$source_root/$policy" >/dev/null || return 1
  # These expressions intentionally remain literal source contracts, matching
  # the packaged publisher. Runtime policy/identity tests run independently.
  # shellcheck disable=SC2016
  local needles=(
    'python3 "$cache_policy_source" check --product "$DECISION_PRODUCT"'
    'DISTRIBUTION_CLOSURE_METADATA="$metadata" maestro-ci-distribution-restore'
    'python3 "$cache_policy_source" scope --product "$DECISION_PRODUCT"'
    '--retained "$metadata" --output "$cache_metadata"'
    'cache_readback+=(--closure-metadata "$cache_metadata")'
    'publication_admission'
    "jq -er '.missing[]'"
    'cachix push maestro'
  )
  local needle
  for needle in "${needles[@]}"; do
    has_text "$source_root" "$relative" "$needle" || return 1
  done
  has_text "$source_root" "$candidate" 'cache_publication.attach(product,' || return 1
  has_text "$source_root" "$candidate" 'for v in [*product["products"].values(), *product["roots"].values()]' || return 1
  has_text "$source_root" "$candidate" 'scans["transport"] = module.export(output, list(roots.values()))' || return 1
  has_text "$source_root" "$restore" 'common.gate(cfg, scan_path, product_path,' || return 1
  has_text "$source_root" "$restore" 'for v in [*product["products"].values(), *product.get("roots", {}).values()]' || return 1
  has_text "$source_root" "$restore" 'module.restore(Path(os.environ["DECISION_EVIDENCE_DIRECTORY"]), scan["transport"], list(roots.values()),' || return 1
  has_text "$source_root" "$verifier" 'require(actual == signed,' || return 1
  has_text "$source_root" "$verifier" "retained[path].get('narHash') == row['narHash']" || return 1
}

check_contract "$root" || { printf '%s\n' 'Scoped cache and complete retained distribution contract failed' >&2; exit 1; }

# Each dropped boundary must fail independently. These are small source
# mutations in disposable fixtures, never edits to the actual repository.
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
for file in "$relative" "$candidate" "$restore" "$verifier" "$policy"; do
  mkdir -p "$temporary/base/$(dirname "$file")"
  cp "$root/$file" "$temporary/base/$file"
done
for mutation in scope-check scope-output full-restore full-subjects full-export restore-gate signed-graph; do
  cp -R "$temporary/base" "$temporary/$mutation"
  file=$relative
  # shellcheck disable=SC2016
  case "$mutation" in
    scope-check) needle='python3 "$cache_policy_source" check' ;;
    scope-output) needle='cache_readback+=(--closure-metadata "$cache_metadata")' ;;
    full-restore) needle='DISTRIBUTION_CLOSURE_METADATA="$metadata" maestro-ci-distribution-restore' ;;
    full-subjects) file=$candidate; needle='for v in [*product["products"].values(), *product["roots"].values()]' ;;
    full-export) file=$candidate; needle='scans["transport"] = module.export(output, list(roots.values()))' ;;
    restore-gate) file=$restore; needle='common.gate(cfg, scan_path, product_path,' ;;
    signed-graph) file=$verifier; needle='require(actual == signed,' ;;
  esac
  grep -Fv -- "$needle" "$temporary/$mutation/$file" >"$temporary/changed"
  mv "$temporary/changed" "$temporary/$mutation/$file"
  if check_contract "$temporary/$mutation"; then
    printf 'Contract accepted removed boundary: %s\n' "$mutation" >&2
    exit 1
  fi
done
cp -R "$temporary/base" "$temporary/commented"
while IFS= read -r line; do
  # shellcheck disable=SC2016
  if [[ $line == *'python3 "$cache_policy_source" check'* ]]; then
    printf '# %s\n' "$line"
  else
    printf '%s\n' "$line"
  fi
done <"$temporary/base/$relative" >"$temporary/commented/$relative"
if check_contract "$temporary/commented"; then
  printf '%s\n' 'Contract accepted a commented-out scope boundary' >&2
  exit 1
fi
jq '.cachePublication.roots += ["toplevel"]' "$temporary/base/$policy" >"$temporary/changed"
mv "$temporary/changed" "$temporary/base/$policy"
if check_contract "$temporary/base"; then
  printf '%s\n' 'Contract accepted an unapproved appliance cache root' >&2
  exit 1
fi
printf '%s\n' 'Signed cache scope, complete retained distribution and nine negative wiring fixtures passed.'
