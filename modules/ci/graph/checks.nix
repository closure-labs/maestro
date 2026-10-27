{
  inputs,
  lib,
  ...
}: {
  perSystem = {
    pkgs,
    system,
    maestroCi,
    ...
  }: let
    packages = inputs.self.packages.${system};
    appliance = inputs.self.nixosConfigurations.maestro.config;
  in {
    checks = {
      ci-plan-contract = let
        plans = inputs.self.lib.ciPlans.${system};
        qualificationInputs = inputs.self.lib.ciQualificationInputs.${system};
        inventoryRoots = lib.sort builtins.lessThan (lib.unique (lib.concatMap
          (target: builtins.attrValues target.outputs)
          inputs.self.lib.ciGraph.${system}.transport.inventory));
        authenticatedRoots = lib.sort builtins.lessThan (lib.unique maestroCi.distributionRoots);
        unsupportedInstaller = initrd:
          builtins.tryEval (import ../../features/installer/_lib/qualification.nix {
            inherit lib;
            installerIso = null;
            installerSystem = {
              inherit pkgs;
              config = {
                boot = {inherit initrd;};
                specialisation = {};
              };
            };
          });
      in
        assert !(unsupportedInstaller {
          systemd.enable = false;
          prepend = [];
        }).success;
        assert !(unsupportedInstaller {
          systemd.enable = true;
          prepend = ["unattributed-archive"];
        }).success;
        assert lib.assertMsg
        ((lib.mapAttrs (_: plan: {inherit (plan) name targets;}) plans)
          == builtins.fromJSON (builtins.readFile ./_lib/plans.json))
        "Generated native plan data is stale; run ci:graph:write-plans";
        assert lib.assertMsg (inventoryRoots == authenticatedRoots)
        "Transport roots must match the default outputs covered by authenticated native inventory";
        assert builtins.length plans.publish.targets == 7;
        assert builtins.attrNames inputs.self.nixosConfigurations == ["maestro"];
        assert packages.distribution-inventory.qualification.system != appliance.system.build.toplevel.outPath;
        assert builtins.all (binding: builtins.elem binding.root (builtins.attrValues packages.distribution-inventory.qualification.roots)) packages.distribution-inventory.qualification.bindings;
        assert qualificationInputs.evidence.toplevel == inputs.self.nixosConfigurations.maestro.config.system.build.toplevel.outPath;
        assert qualificationInputs.media.dependencies.installerIso == packages.installer-iso.outPath;
        assert !(qualificationInputs.media ? source);
          pkgs.runCommandLocal "maestro-ci-plan-contract" {
            nativeBuildInputs = [pkgs.jq];
          } ''
            printf '%s\n' ${lib.escapeShellArg (builtins.toJSON plans)} > plans.json
            jq -e '
              (.validation.schemaVersion == 2) and
              (.validation.name == "maestro-validation") and
              (.validation.targets | length == 20) and
              (.media.schemaVersion == 2) and
              (.media.name == "maestro-media-qualification") and
              (.media.targets | length == 1) and
              (.evidence.schemaVersion == 2) and
              (.evidence.name == "maestro-evidence-qualification") and
              (.evidence.targets | length == 5) and
              (.publish.schemaVersion == 2) and
              (.publish.name == "maestro-publish") and
              (.publish.targets | length == 7)
            ' plans.json >/dev/null
            test -e ${inputs.self.checks.${system}.check-flake-file}
            test -e ${inputs.self.checks.${system}.ci-graph-fixtures}
            touch "$out"
          '';

      qualification-input-fixtures =
        pkgs.runCommandLocal "maestro-qualification-input-fixtures" {
          nativeBuildInputs = [pkgs.bash pkgs.coreutils pkgs.gnused pkgs.jq];
          source = lib.fileset.toSource {
            root = ./.;
            fileset = ./_tests/qualification-inputs.sh;
          };
        } ''
          export MAESTRO_CI_QUALIFICATION_INPUTS=${lib.getExe packages.maestro-ci-qualification-inputs}
          bash "$source/_tests/qualification-inputs.sh"
          touch "$out"
        '';
    };
  };
}
