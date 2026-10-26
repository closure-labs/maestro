#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "${MAESTRO_SYSTEM_ROOT:-$PWD}"
output=$PWD/ci-equivalence
mkdir -p "$output"
candidate=${GITHUB_SHA:?}
base=${EQUIVALENCE_BASE_SHA:-}
[[ $candidate =~ ^[0-9a-f]{40}$ ]]
if [[ -z $base || $base == 0000000000000000000000000000000000000000 ]]; then
  base=$(git rev-parse "$candidate^")
fi
[[ $base =~ ^[0-9a-f]{40}$ ]]
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
# Enforce migration equivalence while the immutable base predates this graph.
# Once the graph is established, legitimate policy/input updates remain possible;
# their observed differences are retained and ordinary qualification still runs.
export EQUIVALENCE_MIGRATION_MODE=true
if base_graph=$(nix eval --accept-flake-config --no-write-lock-file --json \
  "path:$work/base#lib.ciGraph.x86_64-linux.schemaVersion" 2>"$output/base-graph.log") && [[ $base_graph == 1 ]]; then
  EQUIVALENCE_MIGRATION_MODE=false
fi
if ! diff -u "$output/base.security.json" "$output/candidate.security.json" >"$output/security.diff"; then
  if [[ $EQUIVALENCE_MIGRATION_MODE == true ]]; then
    cat "$output/security.diff" >&2
    exit 1
  fi
fi
python3 - "$output" "$work" "$EQUIVALENCE_MIGRATION_MODE" <<'PY'
import json,sys
from pathlib import Path
out,work=map(Path,sys.argv[1:3])
for kind in ['packages','apps','checks']:
    before=json.loads((out/f'base.{kind}.json').read_text())
    after=json.loads((out/f'candidate.{kind}.json').read_text())
    if set(before)-set(after):raise ValueError('Removed public outputs: '+repr(set(before)-set(after)))
before=json.loads((work/'base/flake.lock').read_text())['nodes']
after=json.loads((work/'candidate/flake.lock').read_text())['nodes']
# Node names may be renumbered; compare every existing reachable input binding,
# resolving follows and guarding cycles rather than accepting unused old nodes.
def resolve(nodes, reference, trail=()):
    if isinstance(reference,str):return reference
    if not isinstance(reference,list) or tuple(reference) in trail:
        raise ValueError('Invalid or cyclic input follows')
    node='root'
    for segment in reference:
        node=resolve(nodes,nodes[node]['inputs'][segment],trail+(tuple(reference),))
    return node
seen=set()
def unchanged(old_name,new_name,path):
    key=(old_name,new_name)
    if key in seen:return
    seen.add(key)
    old,new=before[old_name],after[new_name]
    if old.get('locked') != new.get('locked') or old.get('flake',True) != new.get('flake',True):
        raise ValueError('Existing input changed: '+path)
    for name,reference in old.get('inputs',{}).items():
        if name not in new.get('inputs',{}):raise ValueError('Existing input removed: '+path+'/'+name)
        unchanged(resolve(before,reference),resolve(after,new['inputs'][name]),path+'/'+name)
if sys.argv[3] == 'true':
    for name,reference in before['root']['inputs'].items():
        unchanged(resolve(before,reference),resolve(after,after['root']['inputs'][name]),name)

PY
nix eval --accept-flake-config --no-write-lock-file --json \
  "path:$work/candidate#lib.ciGraph.x86_64-linux" >"$output/original.graph.json"
python3 "$MAESTRO_EQUIVALENCE_SOURCE" "$work/candidate" "$output" "$candidate" "$base"
