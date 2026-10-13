{
  inputs,
  lib,
  ...
}: let
  systems = ["x86_64-linux"];
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
  flake.apps = lib.genAttrs systems (
    system: let
      pkgs = import inputs.nixpkgs {
        inherit system;
        config.allowUnfreePredicate = package:
          lib.getName package == "packer";
      };
      maestroctl = inputs.self.packages.${system}.maestroctl;
      maestroMenu = inputs.self.packages.${system}.maestro-menu;
      planRunner = inputs.self.packages.${system}.flake-plan-runner;
      bootstrap = inputs.self.packages.${system}.bootstrap;
      buildTemplate = inputs.self.packages.${system}.build-template;
      deployTemplate = inputs.self.packages.${system}.deploy-template;
      # The native evaluator can return a literal patch's store path before
      # materializing it on a cold runner. Realizing the appliance's coreutils
      # through the outer Nix CLI also materializes its stdenv source inputs.
      devenv = pkgs.writeShellApplication {
        name = "devenv";
        runtimeInputs = [pkgs.coreutils];
        text = ''
          exec ${lib.getExe inputs.devenv.packages.${system}.devenv} "$@"
        '';
      };
      maestroctlApp = mkMaestroctlApp pkgs maestroctl;
    in {
      devenv = {
        type = "app";
        program = lib.getExe devenv;
        meta.description = "Run the pinned native devenv task and shell interface";
      };

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

      bootstrap = {
        type = "app";
        program = lib.getExe bootstrap;
        meta.description = "Bootstrap the fixed maestro appliance checkout";
      };

      build-template = {
        type = "app";
        program = lib.getExe buildTemplate;
        meta.description = "Build a native Maestro XCP-ng template with Packer";
      };

      deploy-template = {
        type = "app";
        program = lib.getExe deployTemplate;
        meta.description = "Build and deploy a native Maestro XCP-ng template";
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

      menu = {
        type = "app";
        program = "${maestroMenu}/bin/maestro-menu";
        meta.description = "Launch the Maestro SSH administration TUI";
      };

      run-ci-plan = {
        type = "app";
        program = lib.getExe planRunner;
        meta.description = "Validate and execute a pure flake CI plan";
      };
    }
  );
}
