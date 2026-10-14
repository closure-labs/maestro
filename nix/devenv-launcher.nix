{
  pkgs,
  lib,
  devenv,
}: let
  # A substituted runtime closure excludes build-time sources. Materialize
  # literal patches through the outer evaluator before the native evaluator.
  sourcePatches = builtins.filter builtins.isPath (pkgs.coreutils.patches or []);
in
  pkgs.writeShellApplication {
    name = "devenv";
    runtimeInputs = [pkgs.coreutils];
    text = ''
      for patch in ${lib.escapeShellArgs (map (patch: "${patch}") sourcePatches)}; do
        test -r "$patch"
      done
      exec ${lib.getExe devenv} "$@"
    '';
  }
