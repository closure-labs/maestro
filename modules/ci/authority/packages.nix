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
    context = {
      inherit pkgs planRunner packerXenserver ciNix installerQualification;
      commands =
        lib.mapAttrs' (name: package: lib.nameValuePair (lib.removePrefix "maestro-ci-" name) package)
        (lib.filterAttrs (name: _: lib.hasPrefix "maestro-ci-" name) inputs.self.packages.${system});
      common = import ./_lib/common.nix {inherit pkgs ciNix;};
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
    _module.args.maestroCi = context;
    packages.flake-plan-runner = planRunner;
  };
}
