{
  inputs,
  lib,
  ...
}: let
  mkMaestroctlApp = pkgs: maestroctl: {
    appName,
    args,
    description,
  }: {
    type = "app";
    program = toString (
      pkgs.writeShellScript appName ''
        set -euo pipefail
        exec ${maestroctl}/bin/maestroctl ${lib.escapeShellArgs args} "$@"
      ''
    );
    meta.description = description;
  };
in {
  perSystem = {
    pkgs,
    config,
    system,
    ...
  }: let
    maestroctl = config.packages.maestroctl;
    maestroMenu = config.packages.maestro-menu;
    planRunner = config.packages.flake-plan-runner;
    bootstrap = config.packages.bootstrap;
    buildTemplate = config.packages.build-template;
    deployTemplate = config.packages.deploy-template;
    devenv = import ../../../../nix/devenv-launcher.nix {
      inherit pkgs lib;
      devenv = inputs.devenv.packages.${system}.devenv;
    };
    maestroctlApp = mkMaestroctlApp pkgs maestroctl;
  in {
    apps = {
      menu = {
        type = "app";
        program = "${maestroMenu}/bin/maestro-menu";
        meta.description = "Launch the Maestro SSH administration TUI";
      };
    };
  };
}
