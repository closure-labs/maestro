#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
case ${GITHUB_EVENT_NAME:-} in workflow_run|workflow_dispatch|schedule) ;; *)
  echo 'Publication requires the trusted completed-candidate controller.' >&2; exit 2 ;;
esac
[[ ${GITHUB_REF:-} == refs/heads/main ]]
: "${DECISION_PRODUCT:?}" "${DECISION_SCANS:?}"
# No evaluation or builders run in this credentialed publisher. The producer
# already realized, inventoried and attested every exact root.
PUBLICATION_PURPOSE=rolling maestro-ci-decision-publication
# Inspect public identities before importing or transferring any closure.
destination_state=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/publication-cache.XXXXXX")
trap 'rm -f -- "$destination_state"' EXIT
python3 "${PUBLICATION_DESTINATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/destinations.py}" cache --product "$DECISION_PRODUCT" --cache-url "https://maestro.cachix.org" ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"} >"$destination_state"
if [[ $(jq -er .status "$destination_state") == verified ]]; then
  PUBLICATION_PURPOSE=rolling maestro-ci-decision-publication
  echo 'Public cache verified; no closure import or upload required.'
  exit 0
fi
PUBLICATION_PURPOSE=rolling maestro-ci-distribution-restore
: "${CACHIX_MAESTRO_AUTH_TOKEN:?}" "${CACHIX_MAESTRO_PUBKEY:?}"
[[ $CACHIX_MAESTRO_PUBKEY == 'maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0=' ]]
mapfile -t outputs < <(jq -er '[.products[].storePath, .roots[].storePath] | unique[]' "$DECISION_PRODUCT")
[[ ${#outputs[@]} -gt 0 ]]
metadata=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-publish-nars.XXXXXX")
trap 'rm -f -- "$metadata" "$destination_state"' EXIT
nix path-info --json "${outputs[@]}" >"$metadata"
python3 - "$DECISION_PRODUCT" "$metadata" <<'PYTHON'
import json
from pathlib import Path
import sys
product, records = (json.loads(Path(p).read_text()) for p in sys.argv[1:])
if isinstance(records, list):
    records = {r['path']: r for r in records}
for value in [*product['products'].values(), *product.get('roots', {}).values()]:
    if records.get(value['storePath'], {}).get('narHash') != value['narHash']:
        raise ValueError('Realized distribution output differs from qualified NAR identity')
PYTHON
# Recheck live authority after store verification, immediately before writing.
PUBLICATION_PURPOSE=rolling maestro-ci-decision-publication
maestro-ci-decision-handoff
export CACHIX_AUTH_TOKEN="$CACHIX_MAESTRO_AUTH_TOKEN"
jq -er '.missing[]' "$destination_state" | cachix push maestro
# A successful upload can leave an existing same-path object untouched. Confirm
# the public cache serves the approved bytes before the controller checkpoints
# publication or publishes a downstream handoff. Query the remote store directly
# and bypass both positive and negative local narinfo metadata caches.
if ! remote_info=$(timeout --signal=TERM --kill-after=10s 120s \
  nix path-info --store "https://maestro.cachix.org" --json \
  --option narinfo-cache-positive-ttl 0 --option narinfo-cache-negative-ttl 0 \
  "${outputs[@]}" 2>/dev/null); then
  echo 'Public cache readback failed' >&2
  exit 1
fi
if ! jq -se --slurpfile product "$DECISION_PRODUCT" '
  (if length == 1 then .[0] else error("invalid remote JSON stream") end)
  |
  (if type == "array" then map({storePath: .path, narHash})
   elif type == "object" then to_entries | map({storePath: .key, narHash: .value.narHash})
   else error("invalid remote path metadata") end | sort_by(.storePath))
  == ([$product[0].products[], $product[0].roots[]]
      | map({storePath, narHash}) | unique | sort_by(.storePath))
' <<< "$remote_info" >/dev/null 2>&1; then
  echo 'Public cache paths or NAR hashes differ from the approved product' >&2
  exit 1
fi

# Persist only fresh remote proof; an older completion is never sufficient.
python3 "${PUBLICATION_DESTINATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/destinations.py}" cache --product "$DECISION_PRODUCT" --cache-url "https://maestro.cachix.org" --require-verified ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"}
