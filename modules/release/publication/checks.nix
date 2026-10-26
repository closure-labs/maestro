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
    mkSourceCheck = import ../../ci/checks/_lib/source-check.nix {inherit pkgs lib inputs packages fixtureInputs;};
  in {
    checks = {
      release-fixtures = mkSourceCheck {
        name = "release-fixtures";
        command = ''
          bash ./tests/release-assets.sh
          bash ./tests/release-attestations.sh
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 tests/release-request.py
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 tests/release-graph.py
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 tests/pilot-benchmark.py
        '';
        nativeBuildInputs = fixtureInputs ++ [pkgs.yq-go];
      };
    };
  };
}
