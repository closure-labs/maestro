{lib, ...}: let
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
    ...
  }: let
    maestroctl = config.packages.maestroctl;
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
