#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${MAESTRO_SBOMNIX:?MAESTRO_SBOMNIX must identify the packaged sbomnix executable}"
temporary=$(mktemp -d)
cleanup() {
  status=$?
  if ((status != 0)); then
    for log in "$temporary/output.log" "$temporary/runtime.trace"; do
      [[ ! -f "$log" ]] || cat "$log" >&2
    done
  fi
  rm -rf -- "$temporary"
  exit "$status"
}
trap cleanup EXIT
mkdir -p "$temporary/bin" "$temporary/root" "$temporary/selected" "$temporary/wrong" "$temporary/cache"
export GITHUB_ACTIONS=true MAESTRO_CI_NIX_BIN="$temporary/bin/nix"
export RUNTIME_LOCK_ROOT="$temporary" RUNTIME_TRACE="$temporary/runtime.trace" TMPDIR="$temporary/cache"
printf '#!%s\n' "$BASH" >"$MAESTRO_CI_NIX_BIN"
cat >>"$MAESTRO_CI_NIX_BIN" <<'RUNTIME'
set -euo pipefail
printf '%s\n' "${0##*/}" "$@" >>"$RUNTIME_TRACE"
if [[ ${0##*/} == nix && ${1:-} == flake && ${2:-} == metadata ]]; then
  if [[ ${3:-} == "path:$RUNTIME_LOCK_ROOT/root" ]]; then
    cat "$RUNTIME_LOCK_ROOT/graph.json"
  elif [[ ${3:-} == "path:$RUNTIME_LOCK_ROOT/selected" || ${3:-} == "path:$RUNTIME_LOCK_ROOT/wrong" ]]; then
    jq -n --arg path "${3#path:}" '{path:$path,description:"A collection of packages for the Nix package manager"}'
  else
    exit 78
  fi
  exit 0
fi
exit 77
RUNTIME
chmod +x "$MAESTRO_CI_NIX_BIN"
cp "$MAESTRO_CI_NIX_BIN" "$temporary/bin/nix-env"

write_graph() {
  jq -n --arg root "$temporary/root" --arg selected "$temporary/selected" --arg wrong "$temporary/wrong" --arg mode "$1" '
    {path:$root, locks:{root:"appliance",nodes:{
      appliance:{inputs:{nixpkgs:"nixpkgs_5", dependency:"dependency"}},
      nixpkgs:{locked:{type:"path",path:$wrong}},
      nixpkgs_5:{locked:{type:"path",path:$selected}},
      dependency:{inputs:{nixpkgs:["selected"]}}
    }}}
    | if $mode=="follows" then .locks.nodes.appliance.inputs.nixpkgs=["dependency","nixpkgs"] | .locks.nodes.appliance.inputs.selected="nixpkgs_5"
      elif $mode=="cycle" then .locks.nodes.appliance.inputs.nixpkgs=["dependency","nixpkgs"] | .locks.nodes.dependency.inputs.nixpkgs=["nixpkgs"]
      elif $mode=="missing" then .locks.nodes.appliance.inputs.nixpkgs="absent"
      elif $mode=="invalid" then .locks.nodes.appliance.inputs.nixpkgs=42
      elif $mode=="empty" then .locks.nodes.appliance.inputs.nixpkgs=[]
      elif $mode=="bad-follow" then .locks.nodes.appliance.inputs.nixpkgs=["dependency",null]
      elif $mode=="bad-value" then .locks.nodes.nixpkgs_5.locked.path=[]
      elif $mode=="unsupported" then .locks.nodes.nixpkgs_5.locked.type="unknown"
      elif $mode=="incomplete" then del(.locks.nodes.nixpkgs_5.locked.path)
      elif $mode=="unlocked" then del(.locks.nodes.nixpkgs_5.locked)
      elif $mode=="bad-root" then .locks.root="absent"
      elif $mode=="missing-input" then del(.locks.nodes.appliance.inputs.nixpkgs)
      else . end' >"$temporary/graph.json"
}
for mode in direct follows; do
  write_graph "$mode"
  rm -f "$RUNTIME_TRACE"
  if "${MAESTRO_SBOMNIX%/*}/nixmeta" --flakeref "path:$temporary/root" --out "$temporary/meta.csv" >"$temporary/output.log" 2>&1; then
    echo "nixmeta ignored the captured companion failure: $mode" >&2
    exit 1
  fi
  grep -Fx -- nix-env "$RUNTIME_TRACE" >/dev/null
  grep -Fx -- "path:$temporary/selected" "$RUNTIME_TRACE" >/dev/null
  grep -Fx -- "$temporary/selected" "$RUNTIME_TRACE" >/dev/null
  if grep -Fx -- "path:$temporary/wrong" "$RUNTIME_TRACE" >/dev/null; then
    echo 'nixmeta selected the misleading first nixpkgs node' >&2
    exit 1
  fi
done
for mode in cycle missing invalid empty bad-follow unlocked bad-root missing-input unsupported incomplete bad-value; do
  write_graph "$mode"
  rm -f "$RUNTIME_TRACE"
  if "${MAESTRO_SBOMNIX%/*}/nixmeta" --flakeref "path:$temporary/root" --out "$temporary/meta.csv" >"$temporary/output.log" 2>&1; then
    echo "nixmeta accepted a malformed lock graph: $mode" >&2
    exit 1
  fi
  grep -E 'ValueError: (Cyclic nixpkgs follows path|Missing nixpkgs lock node|Malformed.*nixpkgs|Unsupported or incomplete root nixpkgs lock metadata)' "$temporary/output.log" >/dev/null
  if grep -Fx -- nix-env "$RUNTIME_TRACE" >/dev/null; then
    echo "nixmeta evaluated an invalid lock graph: $mode" >&2
    exit 1
  fi
done
echo 'Packaged sbomnix root lock selection and follows fixtures passed'
