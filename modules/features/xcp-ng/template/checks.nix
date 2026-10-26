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
    appliance = inputs.self.nixosConfigurations.maestro.config;
    xoPackages = inputs.xen-orchestra-ce.packages.${system};
    managementCIDRType = inputs.self.nixosConfigurations.maestro.options.maestro.operator.managementCIDRs.type.nestedTypes.elemType;
    xoConfigFeatures = ["http" "redis" "remotes" "web"];
    xoConfigFragments = appliance.maestro.xo.internal.configFragments;
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
        source = lib.fileset.toSource {
          root = ../../../..;
          fileset = lib.fileset.unions [./_source ../../../../nix/automation/packer-validate.sh];
        };
        command = "${lib.getExe packages.maestro-ci-packer-validate}";
      };
    };
  };
}
