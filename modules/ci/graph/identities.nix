{
  inputs,
  config,
  lib,
  ...
}: let
  system = "x86_64-linux";
  mkPlan = inputs.xen-orchestra-ce.lib.mkCiPlan;
  targets = config.maestro.ci.targets;
  definitions =
    lib.mapAttrs (phase: name: {
      inherit name;
      targets =
        map (target: {inherit (target) name attribute;} // lib.optionalAttrs (target.link != null) {inherit (target) link;})
        (lib.sort (a: b: a.order.${phase} < b.order.${phase})
          (lib.filter (target: builtins.elem phase target.phases) (builtins.attrValues targets)));
    }) {
      validation = "maestro-validation";
      media = "maestro-media-qualification";
      evidence = "maestro-evidence-qualification";
      publish = "maestro-publish";
    };
  validTarget = target: target ? name && target ? attribute;
  validPlan = plan: builtins.all validTarget plan.targets;
in {
  flake.lib.ciGraph.${system} = {
    schemaVersion = 1;
    mode =
      if config.maestro.ci.gatingEnabled
      then "active"
      else "shadow";
    gatingEnabled = config.maestro.ci.gatingEnabled;
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
    transport = let
      root = attribute: let
        derivation = lib.attrByPath (lib.splitString "." attribute) null inputs.self;
      in {
        inherit attribute;
        derivation = derivation.drvPath;
        # Only the selected output is distributed by ciPlans. Other outputs
        # may exist after a source build but are absent from signed restores.
        outputs.out = derivation.outPath;
      };
      installerContents =
        lib.mapAttrsToList (name: path: {
          attribute = "lib.ciInstallerQualification.${system}.roots.${name}";
          # Copied origins can carry several recipe contexts. Preserve all
          # contexts instead of inventing one producer from the first key.
          sourceContexts = builtins.getContext path;
          outputs.out = path;
        })
        inputs.self.lib.ciInstallerQualification.${system}.roots;
      appliance =
        map (target: root target.attribute)
        (definitions.evidence.targets ++ definitions.publish.targets);
      installer = [(root "packages.x86_64-linux.installer-iso")] ++ installerContents;
    in {
      inherit appliance installer;
      inventory =
        map (target: root target.attribute) definitions.publish.targets
        ++ installerContents;
    };
    policy = {
      qualificationInputs = builtins.hashString "sha256" (builtins.toJSON inputs.self.lib.ciQualificationInputs.${system});
      boot = import ../../features/installer/_lib/boot-policy.nix;
      bootVerifier = inputs.self.packages.${system}.maestro-ci-boot-evidence.drvPath;
      bootCommand = builtins.hashFile "sha256" ../../features/installer/_source/boot-media.sh;
      scanner = inputs.self.packages.${system}.maestro-ci-security-scan.drvPath;
      authorityVerifier = inputs.self.packages.${system}.maestro-ci-decision-admission.drvPath;
      scan = builtins.hashFile "sha256" ../security/_source/security-policy.json;
      verifier = builtins.hashFile "sha256" ./_source/transfer.py;
      authority = builtins.hashFile "sha256" ../authority/_source/decision-policy.json;
    };
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
      bootExecution = inputs.self.packages.${system}.maestro-ci-boot-media.drvPath;
      bootVerifier = inputs.self.packages.${system}.maestro-ci-boot-evidence.drvPath;
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
      derivations = {
        installerIso = inputs.self.packages.${system}.installer-iso.drvPath;
        applianceToplevel = inputs.self.nixosConfigurations.maestro.config.system.build.toplevel.drvPath;
      };
      bootPolicy = import ../../features/installer/_lib/boot-policy.nix;
    };
    evidence = {
      inventoryGenerator = inputs.self.packages.${system}.maestro-ci-security-inventory.drvPath;
      inventoryVerifier = inputs.self.packages.${system}.maestro-ci-security-native-check.drvPath;
      distribution = inputs.self.packages.${system}.distribution-inventory.outPath;
      toplevel = inputs.self.nixosConfigurations.maestro.config.system.build.toplevel.outPath;
      sbomnix = inputs.self.packages.${system}.sbomnix.outPath;
      xenOrchestra = inputs.self.packages.${system}.xen-orchestra-ce.outPath;
      xenOrchestraSupply = inputs.self.packages.${system}.xen-orchestra-supply-protector.outPath;
      derivations = {
        distribution = inputs.self.packages.${system}.distribution-inventory.drvPath;
        toplevel = inputs.self.nixosConfigurations.maestro.config.system.build.toplevel.drvPath;
        sbomnix = inputs.self.packages.${system}.sbomnix.drvPath;
        xenOrchestra = inputs.self.packages.${system}.xen-orchestra-ce.drvPath;
        xenOrchestraSupply = inputs.self.packages.${system}.xen-orchestra-supply-protector.drvPath;
      };
      assetPolicy = builtins.hashString "sha256" (builtins.concatStringsSep "\n" [
        (builtins.hashFile "sha256" ../../features/installer/_source/qualification-assets.sh)
        (builtins.hashFile "sha256" ../authority/_lib/common.nix)
        (builtins.hashFile "sha256" ../inventory/_lib/commands.nix)
        (builtins.hashFile "sha256" ../inventory/_source/assets.sh)
        (builtins.hashFile "sha256" ../inventory/assets.nix)
        (builtins.hashFile "sha256" ../../features/installer/_source/verify-inventory.sh)
        (builtins.hashFile "sha256" ../../features/installer/_source/verify-state.sh)
        (builtins.hashFile "sha256" ../../features/installer/_lib/commands.nix)
        (builtins.hashFile "sha256" ../inventory/_source/security-inventory.py)
        (builtins.hashFile "sha256" ../inventory/_source/security-inventory.sh)
        (builtins.hashFile "sha256" ../security/_source/security-normalize.py)
        (builtins.hashFile "sha256" ../../../.github/workflows/ci.yml)
        (builtins.toJSON definitions.evidence)
      ]);
    };
  };
}
