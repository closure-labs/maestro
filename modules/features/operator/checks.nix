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
      operator-fixtures = mkSourceCheck {
        name = "operator-fixtures";
        command = "MAESTRO_SKIP_EVAL=1 bash ./modules/features/operator/_tests/run.sh";
        nativeBuildInputs = fixtureInputs ++ [pkgs.yq-go pkgs.openssh pkgs.gh (import ../../ci/graph/_lib/nix.nix {inherit pkgs;})];
      };
    };
  };
}
