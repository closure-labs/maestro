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
    packages = inputs.self.packages.${system};
    fixtureInputs = [
      pkgs.bash
      pkgs.coreutils
      pkgs.findutils
      pkgs.git
      pkgs.gnugrep
      pkgs.gnused
      pkgs.jq
    ];
    mkSourceCheck = import ../../../ci/checks/_lib/source-check.nix {inherit pkgs lib inputs packages fixtureInputs;};
  in {
    checks = {
      packer-policy = mkSourceCheck {
        name = "packer-policy";
        exportCommands = false;
        source = lib.fileset.toSource {
          root = ../../../..;
          fileset = lib.fileset.unions [./_source ./_source/packer-validate.sh];
        };
        command = "${lib.getExe packages.maestro-ci-packer-validate}";
      };
    };
  };
}
