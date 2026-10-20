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
PUBLICATION_PURPOSE=rolling maestro-ci-distribution-restore
: "${CACHIX_MAESTRO_AUTH_TOKEN:?}" "${CACHIX_MAESTRO_PUBKEY:?}"
[[ $CACHIX_MAESTRO_PUBKEY == 'maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0=' ]]
mapfile -t outputs < <(jq -er '[.products[].storePath, .roots[].storePath] | unique[]' "$DECISION_PRODUCT")
[[ ${#outputs[@]} -gt 0 ]]
metadata=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-publish-nars.XXXXXX")
trap 'rm -f -- "$metadata"' EXIT
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
printf '%s\n' "${outputs[@]}" | cachix push maestro
