{inputs, ...}: {
  perSystem = {
    pkgs,
    system,
    lib,
    config,
    ...
  }: {
    packages.secretspec = pkgs.callPackage ../../../nix/pkgs/secretspec.nix {};
    packages.maestro-ci-toolchain = pkgs.buildEnv {
      name = "maestro-ci-toolchain";
      paths = [
        (import ../../../nix/devenv-launcher.nix {
          inherit pkgs lib;
          devenv = inputs.devenv.packages.${system}.devenv;
        })
        config.packages.flake-plan-runner
      ];
    };
  };
}
