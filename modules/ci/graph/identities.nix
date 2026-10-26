{
  inputs,
  config,
  lib,
  ...
}: let
  system = "x86_64-linux";
  mkPlan = inputs.xen-orchestra-ce.lib.mkCiPlan;
  targets = config.maestro.ci.targets;
  definitions = lib.mapAttrs (phase: plan:
    plan
    // {
      targets =
        map (target: {inherit (target) name attribute;} // lib.optionalAttrs (target.link != null) {inherit (target) link;})
        (lib.sort (a: b: a.order.${phase} < b.order.${phase})
          (lib.filter (target: builtins.elem phase target.phases) (builtins.attrValues targets)));
    }) (builtins.fromJSON (builtins.readFile ../../../nix/ci-plans.json));
  validTarget = target: target ? name && target ? attribute;
  validPlan = plan: builtins.all validTarget plan.targets;
in {
  flake.lib.ciGraph.${system} = {
    schemaVersion = 1;
    mode = "shadow";
    gatingEnabled = false;
    inherit system;
    targets =
      lib.mapAttrs (id: target: let
        derivation = lib.attrByPath (lib.splitString "." target.attribute) null inputs.self;
      in {
        inherit id;
        inherit (target) owner attribute name phases dependencies requirements;
        derivation = derivation.drvPath;
        outputs = lib.genAttrs derivation.outputs (name: derivation.${name}.outPath);
      })
      targets;
    aspectIncludes = {maestro = ["platform" "xcp-ng" "xo" "operator"];};
  };
  flake.lib.ciInstallerQualification.${system} = inputs.self.packages.${system}.distribution-inventory.qualification;
  flake.lib.ciPlans.${system} = assert builtins.all validPlan (builtins.attrValues definitions);
    builtins.mapAttrs (_: mkPlan) definitions;

  # These are identities, not build instructions. The router hashes their
  # canonical JSON so Nix decides whether already-qualified media is still the
  # exact output requested by the current source tree.
  flake.lib.ciQualificationInputs.${system} = {
    media = {
      dependencies = {
        # Exact evaluated media captures every material recipe/input change.
        # Source-only edits elsewhere in packages.nix must not rebuild an ISO.
        installerIso = inputs.self.packages.${system}.installer-iso.outPath;
        # Installer media embeds this closure, including host management policy.
        applianceToplevel = inputs.self.nixosConfigurations.maestro.config.system.build.toplevel.outPath;
        den = inputs.den.outPath;
        determinate = inputs.determinate.outPath;
        homeManager = inputs.home-manager.outPath;
        importTree = inputs.import-tree.outPath;
        nixpkgs = inputs.nixpkgs.outPath;
        xenOrchestra = inputs.xen-orchestra-ce.packages.${system}.latest.outPath;
      };
      bootPolicy = builtins.hashFile "sha256" ../../../nix/automation/boot-media.sh;
    };
    evidence = {
      distribution = inputs.self.packages.${system}.distribution-inventory.outPath;
      toplevel = inputs.self.nixosConfigurations.maestro.config.system.build.toplevel.outPath;
      sbomnix = inputs.self.packages.${system}.sbomnix.outPath;
      xenOrchestra = inputs.self.packages.${system}.xen-orchestra-ce.outPath;
      xenOrchestraSupply = inputs.self.packages.${system}.xen-orchestra-supply-protector.outPath;
      assetPolicy = builtins.hashString "sha256" (builtins.concatStringsSep "\n" [
        (builtins.hashFile "sha256" ../../../nix/automation/qualification-assets.sh)
        (builtins.hashFile "sha256" ../../../nix/automation/default.nix)
        (builtins.hashFile "sha256" ../../../nix/automation/security-inventory.py)
        (builtins.hashFile "sha256" ../../../nix/automation/security-inventory.sh)
        (builtins.hashFile "sha256" ../../../nix/automation/security-normalize.py)
        (builtins.hashFile "sha256" ../../../.github/workflows/ci.yml)
        (builtins.toJSON definitions.evidence)
      ]);
    };
  };
}
