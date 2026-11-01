#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Private prefix for the two existing unprivileged phases, not a new task.
# GNU time's maximum child RSS is not a whole-runner/cgroup memory peak.
if [[ -n ${MAESTRO_CI_MEASURE_PHASE:-} && ${MAESTRO_CI_MEASURED:-false} != true ]]; then
  case $MAESTRO_CI_MEASURE_PHASE in inventory | scan) ;; *) exit 2 ;; esac
  measurement_dir=${RUNNER_TEMP:?}/maestro-qualification-diagnostics
  mkdir -p "$measurement_dir"
  df -B1 --output=size,used,avail /nix/store >"$measurement_dir/$MAESTRO_CI_MEASURE_PHASE.disk-before.txt"
  export MAESTRO_CI_MEASURED=true
  measurement_status=0
  LC_ALL=C "${MAESTRO_CI_TIME:?}" --quiet \
    --format "{\"phase\":\"$MAESTRO_CI_MEASURE_PHASE\",\"elapsedSeconds\":%e,\"maxChildRssKiB\":%M,\"userSeconds\":%U,\"systemSeconds\":%S,\"exitCode\":%x}" \
    --output "$measurement_dir/$MAESTRO_CI_MEASURE_PHASE.resources.json" \
    "$0" "$@" || measurement_status=$?
  # GNU time's %x can be zero on signal termination; retain the real status.
  jq --argjson exitCode "$measurement_status" '.exitCode = $exitCode' \
    "$measurement_dir/$MAESTRO_CI_MEASURE_PHASE.resources.json" \
    >"$measurement_dir/$MAESTRO_CI_MEASURE_PHASE.resources.tmp"
  mv "$measurement_dir/$MAESTRO_CI_MEASURE_PHASE.resources.tmp" \
    "$measurement_dir/$MAESTRO_CI_MEASURE_PHASE.resources.json"
  df -B1 --output=size,used,avail /nix/store >"$measurement_dir/$MAESTRO_CI_MEASURE_PHASE.disk-after.txt"
  exit "$measurement_status"
fi
