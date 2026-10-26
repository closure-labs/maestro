{
  inputs,
  lib,
  ...
}: {
  perSystem = {
    pkgs,
    system,
    ...
  }: let
    devenv = import ./_lib/launcher.nix {
      inherit pkgs lib;
      devenv = inputs.devenv.packages.${system}.devenv;
    };
  in {
    apps.devenv = {
      type = "app";
      program = lib.getExe devenv;
      meta.description = "Run the pinned native devenv task and shell interface";
    };
  };
}
