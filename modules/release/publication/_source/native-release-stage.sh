#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
args=(--iso "${NATIVE_ISO:?}" --output "${NATIVE_RELEASE_OUTPUT:?}"
  --version "${NATIVE_RELEASE_VERSION:?}" --run "${NATIVE_RUN:?}" --attempt "${NATIVE_ATTEMPT:?}" --revision "${NATIVE_REVISION:?}"
  --media-run "${NATIVE_MEDIA_RUN:?}" --media-attempt "${NATIVE_MEDIA_ATTEMPT:?}" --media-revision "${NATIVE_MEDIA_REVISION:?}")
if [[ -n ${NATIVE_DIRECTORY:-} ]]; then
  args+=(--directory "$NATIVE_DIRECTORY")
fi
if [[ -n ${NATIVE_BOOT_ORIGIN_RUN:-} ]]; then
  args+=(--boot-origin-run "$NATIVE_BOOT_ORIGIN_RUN" --boot-origin-attempt "${NATIVE_BOOT_ORIGIN_ATTEMPT:?}" --boot-origin-revision "${NATIVE_BOOT_ORIGIN_REVISION:?}")
else
  [[ -z ${NATIVE_BOOT_ORIGIN_ATTEMPT:-} && -z ${NATIVE_BOOT_ORIGIN_REVISION:-} ]]
fi
if [[ -n ${NATIVE_RELEASE_FINAL_ISO:-} ]]; then
  args+=(--final-iso "$NATIVE_RELEASE_FINAL_ISO")
fi
if [[ -n ${NATIVE_POLICY_REVISION:-} ]]; then
  args+=(--policy-revision "$NATIVE_POLICY_REVISION")
fi
if [[ -n ${NATIVE_HEALTH_RUN:-} ]]; then
  args+=(--health-run "$NATIVE_HEALTH_RUN" --health-attempt "${NATIVE_HEALTH_ATTEMPT:?}")
else
  [[ -z ${NATIVE_HEALTH_ATTEMPT:-} && -z ${NATIVE_HEALTH_DIRECTORY:-} ]]
fi
[[ -z ${NATIVE_HEALTH_DIRECTORY:-} ]] || args+=(--health-directory "$NATIVE_HEALTH_DIRECTORY")
exec python3 "$MAESTRO_NATIVE_RELEASE_STAGE_SOURCE" "${args[@]}" "$@"
