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
      maestroctl = {
        type = "app";
        program = "${maestroctl}/bin/maestroctl";
        meta.description = "Canonical Maestro operator CLI";
      };

      apply = maestroctlApp {
        appName = "maestro-apply";
        args = ["apply"];
        description = "Apply a Maestro host configuration through maestroctl";
      };

      commit = maestroctlApp {
        appName = "maestro-commit";
        args = ["commit"];
        description = "Commit Maestro repository changes through maestroctl";
      };

      diff = maestroctlApp {
        appName = "maestro-diff";
        args = ["diff"];
        description = "Show Maestro repository changes through maestroctl";
      };

      history = maestroctlApp {
        appName = "maestro-history";
        args = ["history"];
        description = "Show Maestro repository history through maestroctl";
      };
    };
  };
}
