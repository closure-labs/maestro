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
  in {
    checks = {
      sbomnix-runtime =
        pkgs.runCommandLocal "maestro-sbomnix-runtime" {
          nativeBuildInputs = fixtureInputs;
        } ''
          export MAESTRO_SBOMNIX=${lib.getExe packages.sbomnix}
          bash ${../checks/_tests/sbomnix-runtime.sh}
          bash ${../checks/_tests/sbomnix-lock-root.sh}
          touch "$out"
        '';
    };
  };
}
