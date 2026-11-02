#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
args=("$@" --run "${NATIVE_RUN:?}" --attempt "${NATIVE_ATTEMPT:?}" --revision "${NATIVE_REVISION:?}")
[[ -z ${NATIVE_DIRECTORY:-} ]] || args+=(--directory "$NATIVE_DIRECTORY")
if [[ -n ${NATIVE_BOOT_ORIGIN_RUN:-} ]]; then
  args+=(--boot-origin-run "$NATIVE_BOOT_ORIGIN_RUN" --boot-origin-attempt "${NATIVE_BOOT_ORIGIN_ATTEMPT:?}" --boot-origin-revision "${NATIVE_BOOT_ORIGIN_REVISION:?}")
else
  [[ -z ${NATIVE_BOOT_ORIGIN_ATTEMPT:-} && -z ${NATIVE_BOOT_ORIGIN_REVISION:-} ]]
fi
exec python3 "$MAESTRO_NATIVE_PUBLICATION_SOURCE" "${args[@]}"
