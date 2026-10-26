{...}: {
  perSystem = {
    pkgs,
    ciNix,
    config,
    ...
  }: {
    packages.maestro-ci-build-appliance = pkgs.writeShellApplication {
      name = "maestro-ci-build-appliance";
      runtimeInputs = [pkgs.git ciNix pkgs.coreutils pkgs.jq config.packages.flake-plan-runner config.packages.maestro-ci-job-transfer config.packages.maestro-ci-security-inventory-preflight config.packages.maestro-ci-qualification-cache];
      text = builtins.readFile ./_source/build.sh;
    };
  };
}
