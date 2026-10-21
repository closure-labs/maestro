#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=${MAESTRO_SYSTEM_ROOT:-$PWD}
if [[ ${PUBLICATION_PURPOSE:-release} == rolling && -z ${PUBLICATION_KEY:-} ]]; then
  PUBLICATION_KEY="rolling-$(python3 -c 'import hashlib,json,sys; print(hashlib.sha256(json.dumps(json.load(open(sys.argv[1])),sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()).hexdigest())' "${DECISION_PRODUCT:?}")"
fi
exec python3 "$MAESTRO_PUBLICATION_JOURNAL_SOURCE" \
  --config "$repo_root/nix/automation/decision-policy.json" \
  --scans "${DECISION_SCANS:?}" --product "${DECISION_PRODUCT:?}" \
  --key "${PUBLICATION_KEY:?}" --step "${PUBLICATION_STEP:?}" \
  --state "${PUBLICATION_STATE:?}" --purpose "${PUBLICATION_PURPOSE:-release}"
