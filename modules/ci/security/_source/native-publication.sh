#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
args=("$@" --run "${NATIVE_RUN:?}" --attempt "${NATIVE_ATTEMPT:?}" --revision "${NATIVE_REVISION:?}")
[[ -z ${NATIVE_DIRECTORY:-} ]] || args+=(--directory "$NATIVE_DIRECTORY")
if [[ -n ${NATIVE_HEALTH_RUN:-} ]]; then
  args+=(--health-run "$NATIVE_HEALTH_RUN" --health-attempt "${NATIVE_HEALTH_ATTEMPT:?}")
  [[ -z ${NATIVE_HEALTH_DIRECTORY:-} ]] || args+=(--health-directory "$NATIVE_HEALTH_DIRECTORY")
else
  [[ -z ${NATIVE_HEALTH_ATTEMPT:-} && -z ${NATIVE_HEALTH_DIRECTORY:-} ]]
fi
if [[ -n ${NATIVE_BOOT_ORIGIN_RUN:-} ]]; then
  args+=(--boot-origin-run "$NATIVE_BOOT_ORIGIN_RUN" --boot-origin-attempt "${NATIVE_BOOT_ORIGIN_ATTEMPT:?}" --boot-origin-revision "${NATIVE_BOOT_ORIGIN_REVISION:?}")
else
  [[ -z ${NATIVE_BOOT_ORIGIN_ATTEMPT:-} && -z ${NATIVE_BOOT_ORIGIN_REVISION:-} ]]
fi
if [[ -n ${NATIVE_POLICY_REVISION:-} ]]; then
  args+=(--policy-revision "$NATIVE_POLICY_REVISION")
fi
if [[ -n ${NATIVE_RELEASE_DIRECTORY:-} ]]; then
  args+=(--release-directory "$NATIVE_RELEASE_DIRECTORY" --release-iso "${NATIVE_RELEASE_ISO:?}")
else
  [[ -z ${NATIVE_RELEASE_ISO:-} ]]
fi
exec python3 "$MAESTRO_NATIVE_PUBLICATION_SOURCE" "${args[@]}"
