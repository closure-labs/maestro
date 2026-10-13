{inputs, ...}: let
  system = "x86_64-linux";
  mkPlan = inputs.xen-orchestra-ce.lib.mkCiPlan;
  definitions = builtins.fromJSON (builtins.readFile ../../nix/ci-plans.json);
  mediaSource = inputs.nixpkgs.lib.fileset.toSource {
    root = ../..;
    fileset = inputs.nixpkgs.lib.fileset.unions [
      ../../flake.nix
      ../../installer
      ../../modules/_homeManager
      ../../modules/_nixos
      ../../modules/aspects
      ../../modules/den-defaults.nix
      ../../modules/dendritic.nix
      ../../modules/host.nix
      ../../modules/outputs/packages.nix
      ../../pkgs/maestro-menu
    ];
  };
  validTarget = target:
    target ? name
    && builtins.isString target.name
    && target ? attribute
    && builtins.isString target.attribute
    && (!target ? link || builtins.isString target.link);
  validPlan = plan:
    plan ? name
    && builtins.isString plan.name
    && plan ? targets
    && builtins.isList plan.targets
    && builtins.all validTarget plan.targets;
in {
  flake.lib.ciPlans.${system} = assert builtins.all validPlan (builtins.attrValues definitions);
    builtins.mapAttrs (_: mkPlan) definitions;

  # These are identities, not build instructions. The router hashes their
  # canonical JSON so Nix decides whether already-qualified media is still the
  # exact output requested by the current source tree.
  flake.lib.ciQualificationInputs.${system} = {
    media = {
      source = mediaSource;
      dependencies = {
        den = inputs.den.outPath;
        determinate = inputs.determinate.outPath;
        homeManager = inputs.home-manager.outPath;
        importTree = inputs.import-tree.outPath;
        nixpkgs = inputs.nixpkgs.outPath;
        xenOrchestra = inputs.xen-orchestra-ce.packages.${system}.latest.outPath;
      };
      bootPolicy = builtins.hashFile "sha256" ../../nix/automation/boot-media.sh;
    };
    evidence = {
      toplevel = inputs.self.nixosConfigurations.maestro.config.system.build.toplevel.outPath;
      sbomnix = inputs.self.packages.${system}.sbomnix.outPath;
      xenOrchestra = inputs.self.packages.${system}.xen-orchestra-ce.outPath;
      xenOrchestraSupply = inputs.self.packages.${system}.xen-orchestra-supply-protector.outPath;
      assetPolicy = builtins.hashString "sha256" (builtins.concatStringsSep "\n" [
        (builtins.hashFile "sha256" ../../nix/automation/qualification-assets.sh)
        (builtins.hashFile "sha256" ../../nix/automation/default.nix)
        (builtins.hashFile "sha256" ../../nix/automation/security-inventory.py)
        (builtins.hashFile "sha256" ../../nix/automation/security-inventory.sh)
        (builtins.hashFile "sha256" ../../nix/automation/security-normalize.py)
        (builtins.hashFile "sha256" ../../.github/workflows/ci.yml)
        (builtins.toJSON definitions.evidence)
      ]);
    };
  };
}
