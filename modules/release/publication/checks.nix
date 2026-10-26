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
    mkSourceCheck = import ../../ci/checks/_lib/source-check.nix {inherit pkgs lib inputs packages fixtureInputs;};
  in {
    checks = {
      release-fixtures = mkSourceCheck {
        name = "release-fixtures";
        command = ''
          bash ./modules/release/publication/_tests/release-assets.sh
          bash ./modules/release/publication/_tests/release-attestations.sh
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 modules/release/publication/_tests/release-request.py
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 modules/release/publication/_tests/release-graph.py
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 modules/ci/graph/_tests/pilot-benchmark.py
        '';
        nativeBuildInputs = fixtureInputs ++ [pkgs.yq-go];
      };
    };
  };
}
