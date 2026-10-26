{inputs, ...}: {
  perSystem = {
    pkgs,
    system,
    lib,
    config,
    ...
  }: {
    packages.secretspec = pkgs.callPackage ./_lib/secretspec.nix {};
    packages.maestro-ci-toolchain = pkgs.buildEnv {
      name = "maestro-ci-toolchain";
      paths = [
        (import ./_lib/launcher.nix {
          inherit pkgs lib;
          devenv = inputs.devenv.packages.${system}.devenv;
        })
        config.packages.flake-plan-runner
      ];
    };
  };
}
