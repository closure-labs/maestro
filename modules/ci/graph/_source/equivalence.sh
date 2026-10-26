#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "${MAESTRO_SYSTEM_ROOT:-$PWD}"
output=$PWD/ci-equivalence
mkdir -p "$output"
candidate=${GITHUB_SHA:?}
base=${EQUIVALENCE_BASE_SHA:?}
[[ $candidate =~ ^[0-9a-f]{40}$ && $base =~ ^[0-9a-f]{40}$ ]]
[[ $(git rev-parse HEAD) == "$candidate" ]]
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/maestro-equivalence.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
for revision in candidate base; do
  mkdir -p "$work/$revision"
  source_revision=$candidate
  [[ $revision != base ]] || source_revision=$base
  git archive "$source_revision" | tar -x -C "$work/$revision"
done
apply='c: {
  operatorOptions = builtins.attrNames c.maestro.operator;
  xoOptions = builtins.attrNames c.maestro.xo;
  ssh = c.services.openssh.settings;
  xo = {inherit (c.maestro.xo) enable channel user group home cacheDir dataDir tempDir;
    package = c.maestro.xo.package.outPath;
    inherit (c.systemd.services.xo-server) serviceConfig;};
  firewall = {inherit (c.networking.firewall) enable allowedTCPPorts allowedUDPPorts;};
  operator = {inherit (c.maestro.operator) username managementCIDRs;};
  determinate = c.determinate.enable;
  gc = c.nix.gc;
  bootGenerations = c.boot.loader.systemd-boot.configurationLimit;
  dbus = {inherit (c.systemd.services.dbus) reloadIfChanged restartIfChanged;};
  dbusBroker = {inherit (c.systemd.services.dbus-broker) reloadIfChanged restartIfChanged;};
  guest = {inherit (c.services.cloud-init) enable network;};
  stateVersion = c.system.stateVersion;
}'
for revision in candidate base; do
  nix eval --accept-flake-config --no-write-lock-file --json \
    "path:$work/$revision#nixosConfigurations.maestro.config" --apply "$apply" | jq -S . >"$output/$revision.security.json"
  for kind in packages apps checks; do
    nix eval --accept-flake-config --no-write-lock-file --json \
      "path:$work/$revision#$kind.x86_64-linux" --apply builtins.attrNames >"$output/$revision.$kind.json"
  done
done
diff -u "$output/base.security.json" "$output/candidate.security.json"
python3 - "$output" "$work" <<'PY'
import json,sys
from pathlib import Path
out,work=map(Path,sys.argv[1:])
for kind in ['packages','apps','checks']:
    before=json.loads((out/f'base.{kind}.json').read_text())
    after=json.loads((out/f'candidate.{kind}.json').read_text())
    if set(before)-set(after):raise ValueError('Removed public outputs: '+repr(set(before)-set(after)))
before=json.loads((work/'base/flake.lock').read_text())['nodes']
after=json.loads((work/'candidate/flake.lock').read_text())['nodes']
# Input graph node names can be renumbered when adding a root. Locked identities
# themselves must all remain present, without opportunistic dependency updates.
identities={json.dumps(v['locked'],sort_keys=True) for v in after.values() if 'locked' in v}
for name,node in before.items():
    if 'locked' in node and json.dumps(node['locked'],sort_keys=True) not in identities:
        raise ValueError('Existing input changed: '+name)
PY
nix eval --accept-flake-config --no-write-lock-file --json \
  "path:$work/candidate#lib.ciGraph.x86_64-linux" >"$output/original.graph.json"
python3 "$MAESTRO_EQUIVALENCE_SOURCE" "$work/candidate" "$output" "$candidate" "$base"
