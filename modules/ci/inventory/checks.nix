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
    mkSourceCheck = import ../checks/_lib/source-check.nix {inherit pkgs lib inputs packages fixtureInputs;};
  in {
    checks = {
      sbomnix-runtime =
        pkgs.runCommandLocal "maestro-sbomnix-runtime" {
          nativeBuildInputs = fixtureInputs;
        } ''
          export MAESTRO_SBOMNIX=${lib.getExe packages.sbomnix}
          bash ${../../../tests/sbomnix-runtime.sh}
          bash ${../../../tests/sbomnix-lock-root.sh}
          touch "$out"
        '';
    };
  };
}
