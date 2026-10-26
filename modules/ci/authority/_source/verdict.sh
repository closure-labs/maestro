#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

test "${ROUTE_RESULT:?}" = success
if [[ ${AUDIT_REQUIRED:-false} == true ]]; then
  [[ ${AUDIT_RESULT:?} == success ]]
else
case "${AUDIT_OVERLAP:-false}" in
  true)
    [[ ${GITHUB_EVENT_NAME:-} == workflow_dispatch ]]
    [[ ${AUDIT_RESULT:?} == success ]]
    ;;
  false) [[ ${AUDIT_RESULT:-skipped} == skipped ]] ;;
  *) printf 'Invalid audit overlap flag\n' >&2; exit 1 ;;
esac
fi
: "${CI_PLAN:?CI_PLAN must contain the route decision JSON output}"

# Legacy v3 plans always use full validation. A v4 descriptor is scheduling data.
jq -e '
  type == "object" and
  ((.schema_version == 3 and (keys | sort) == ["publish_required", "qualification", "schema_version"]) or
   (.schema_version == 4 and (keys | sort) == ["publish_required", "qualification", "retained_evidence", "schema_version"] and
    (.retained_evidence == null or (.retained_evidence | type == "object" and .schema == 1)))) and
  (.publish_required | type == "boolean") and
  (.qualification | type == "object") and
  (.qualification | keys | sort) == [
    "artifact_run_id", "evidence_input", "evidence_run_id", "media_input",
    "media_run_id", "mode", "required"
  ] and
  (.qualification.required | type == "boolean") and
  (.qualification.mode | IN(
    "skip", "reuse", "refresh-evidence",
    "qualify-media-reuse-evidence", "qualify-media"
  )) and
  (if .qualification.required then
    .qualification.mode != "skip" and
    all([
      .qualification.artifact_run_id,
      .qualification.media_run_id,
      .qualification.evidence_run_id
    ][]; type == "number" and floor == . and . >= 1) and
    all([.qualification.media_input, .qualification.evidence_input][];
      type == "string" and test("^[0-9a-f]{64}$"))
  else
    .qualification.mode == "skip" and
    all([
      .qualification.artifact_run_id,
      .qualification.media_run_id,
      .qualification.evidence_run_id,
      .qualification.media_input,
      .qualification.evidence_input
    ][]; . == null)
  end) and
  ((.publish_required | not) or .qualification.required)
' <<<"$CI_PLAN" >/dev/null

mode=$(jq -er '.qualification.mode' <<<"$CI_PLAN")
if [[ ${RETAINED_REUSE:-false} == true ]]; then
  [[ ${MAESTRO_DECISION_ONLY_REUSE_ENABLED:-false} == true && ${RETAINED_RESULT:?} == success ]]
  jq -e '.schema_version == 4 and .retained_evidence != null and .qualification.required' <<<"$CI_PLAN" >/dev/null
  descriptor_hash=$(jq -cSj .retained_evidence <<<"$CI_PLAN" | sha256sum | cut -d' ' -f1)
  [[ ${RETAINED_DESCRIPTOR_HASH:?} == "$descriptor_hash" ]]
  [[ ${QUALIFICATION_RESULT:?} == skipped && ${SECURITY_RESULT:?} == skipped && ${SIGNING_RESULT:-skipped} == skipped ]]
  exit 0
fi
if [[ ${MAESTRO_DECISION_ONLY_REUSE_ENABLED:-false} == true && ${RETAINED_RESULT:-skipped} != skipped ]]; then
  [[ $RETAINED_RESULT == success ]]
fi
if [[ ${SPLIT_QUALIFICATION:-false} == true ]]; then
  case "$mode" in
    qualify-media|qualify-media-reuse-evidence)
      [[ ${APPLIANCE_RESULT:?} == success && ${INSTALLER_RESULT:?} == success ]] ;;
    refresh-evidence)
      [[ ${APPLIANCE_RESULT:?} == success && ${INSTALLER_RESULT:?} == skipped ]] ;;
    reuse|skip)
      [[ ${APPLIANCE_RESULT:?} == skipped && ${INSTALLER_RESULT:?} == skipped ]] ;;
    *) exit 1 ;;
  esac
  if [[ $mode == skip ]]; then
    [[ ${BOOT_RESULT:?} == skipped && ${SCAN_RESULT:?} == skipped ]]
  else
    [[ ${BOOT_RESULT:?} == success && ${SCAN_RESULT:?} == success ]]
  fi
fi
case "$mode" in
  reuse|refresh-evidence|qualify-media-reuse-evidence|qualify-media)
    test "${QUALIFICATION_RESULT:?}" = success
    ;;
  skip)
    test "${QUALIFICATION_RESULT:?}" = skipped
    ;;
  *)
    printf 'Unknown qualification mode: %s\n' "$mode" >&2
    exit 1
    ;;
esac

# Only protected-main runs require signing. Other events must never sign.
if [[ ${GITHUB_REF:-} == refs/heads/main && ${GITHUB_EVENT_NAME:-} =~ ^(push|schedule|workflow_dispatch)$ && $mode != skip ]]; then
  [[ ${SIGNING_RESULT:?} == success ]]
else
  [[ ${SIGNING_RESULT:-skipped} == skipped ]]
fi

if [[ $mode == skip ]]; then
  [[ ${SECURITY_RESULT:?} == skipped ]]
else
  [[ ${SECURITY_RESULT:?} == success ]]
fi
