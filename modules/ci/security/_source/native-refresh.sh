#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
args=(--output "${SECURITY_OUTPUT:-security-report}")
if [[ -n ${NATIVE_OFFICIAL_RELEASE_TAG:-} ]]; then
  [[ ${NATIVE_REFRESH_SELECT_CURRENT_MAIN:-false} != true && -z ${NATIVE_RUN:-} && -z ${NATIVE_ATTEMPT:-} ]]
  [[ -z ${NATIVE_REVISION:-} || ${NATIVE_REVISION} == "${GITHUB_SHA:?}" ]]
  args+=(--official-tag "$NATIVE_OFFICIAL_RELEASE_TAG" --official-publication-revision "${NATIVE_OFFICIAL_PUBLICATION_REVISION:?}")
elif [[ ${NATIVE_REFRESH_SELECT_CURRENT_MAIN:-false} == true ]]; then
  [[ -z ${NATIVE_RUN:-} && -z ${NATIVE_ATTEMPT:-} ]]
  [[ -z ${NATIVE_REVISION:-} || ${NATIVE_REVISION} == "${GITHUB_SHA:?}" ]]
  args+=(--select-current-main)
else
  args+=(--run "${NATIVE_RUN:?}" --attempt "${NATIVE_ATTEMPT:?}" --revision "${NATIVE_REVISION:?}")
fi
[[ -n ${NATIVE_OFFICIAL_RELEASE_TAG:-} || -z ${NATIVE_OFFICIAL_PUBLICATION_REVISION:-} ]]
if [[ -n ${NATIVE_BOOT_ORIGIN_RUN:-} ]]; then
  args+=(--boot-origin-run "$NATIVE_BOOT_ORIGIN_RUN" --boot-origin-attempt "${NATIVE_BOOT_ORIGIN_ATTEMPT:?}"
    --boot-origin-revision "${NATIVE_BOOT_ORIGIN_REVISION:?}")
else
  [[ -z ${NATIVE_BOOT_ORIGIN_ATTEMPT:-} && -z ${NATIVE_BOOT_ORIGIN_REVISION:-} ]]
fi
if [[ -n ${NATIVE_POLICY_REVISION:-} ]]; then
  args+=(--policy-revision "$NATIVE_POLICY_REVISION")
fi
exec python3 "$MAESTRO_NATIVE_REFRESH_SOURCE" "${args[@]}"
