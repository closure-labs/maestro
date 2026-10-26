{inputs, ...}: {
  perSystem = {
    pkgs,
    system,
    lib,
    ciNix,
    packerXenserver,
    installerQualification,
    ...
  }: let
    planRunner = inputs.xen-orchestra-ce.packages.${system}.flake-plan-runner.override {nix = ciNix;};
    commands = import ../../../nix/automation {
      inherit pkgs planRunner packerXenserver ciNix installerQualification;
      devenv = inputs.devenv.packages.${system}.devenv;
      applicabilityCommand = inputs.xen-orchestra-ce.packages.${system}.security-applicability;
      appliance = inputs.self.nixosConfigurations.maestro.config;
      lockFile = ../../../flake.lock;
      packageSourceRoots = [inputs.nixpkgs.outPath inputs.xen-orchestra-ce.inputs.nixpkgs.outPath];
      distributionRoots =
        map (target: (lib.attrByPath (lib.splitString "." target.attribute) null inputs.self).outPath)
        inputs.self.lib.ciPlans.${system}.publish.targets
        ++ builtins.attrValues installerQualification.roots;
    };
  in {
    packages =
      lib.mapAttrs' (name: package: lib.nameValuePair "maestro-ci-${name}" package) commands
      // {
        flake-plan-runner = planRunner;
      };
  };
}
