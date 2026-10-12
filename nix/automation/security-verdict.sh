#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: maestro-ci-security-verdict FINDINGS.json POLICY.json' >&2; exit 2; }
now=$(date -u +%s)
jq -e --argjson now "$now" '
  def key: [.advisory, .component, .version] | join("|");
  def finding: type == "object" and all([.advisory,.component,.version][]; type == "string" and length > 0);
  .schema_version == 1 and (.mode | IN("report", "enforce")) and
  (.baseline | type == "array") and all(.baseline[]; finding and (.severity | IN("high", "critical")) and all([.owner,.reason][]; type == "string" and length > 0)) and
  (.exceptions | type == "array") and all(.exceptions[];
    finding and all([.owner,.reason][]; type == "string" and length > 0) and
    (.created | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
    (.expires | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
    ((.created + "T00:00:00Z" | fromdateiso8601) <= $now) and
    ((.expires + "T00:00:00Z" | fromdateiso8601) > (.created + "T00:00:00Z" | fromdateiso8601)) and
    ((.expires + "T00:00:00Z" | fromdateiso8601) - (.created + "T00:00:00Z" | fromdateiso8601) <= 2592000))
' "$2" >/dev/null
jq -e 'type == "array" and all(.[]; all([.advisory,.component,.version,.severity][]; type == "string" and length > 0))' "$1" >/dev/null
mode=$(jq -er .mode "$2")
violations=$(jq -n --slurpfile findings "$1" --slurpfile policy "$2" --argjson now "$now" '
  def key: [.advisory, .component, .version] | join("|");
  [$policy[0].baseline[] | (key) + "|" + .severity] as $baseline |
  [$policy[0].exceptions[] | select((.expires + "T00:00:00Z" | fromdateiso8601) > $now) | key] as $exceptions |
  [$findings[0][] | select(.severity | ascii_downcase | IN("high", "critical")) |
    . as $finding | (key) as $key |
    select(($baseline | index($key + "|" + ($finding.severity | ascii_downcase))) == null and ($exceptions | index($key)) == null) | $finding]
')
printf '%s\n' "$violations"
if [[ $mode == enforce ]]; then
  [[ $(jq length <<<"$violations") == 0 ]] || {
    echo 'New high/critical vulnerabilities require remediation or an expiring exception.' >&2; exit 1;
  }
else
  echo 'Security policy is report-only pending operator baseline review.' >&2
fi
