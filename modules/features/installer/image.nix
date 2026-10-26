{inputs, ...}: {
  perSystem = {
    system,
    lib,
    config,
    pkgs,
    ...
  }: let
    applianceToplevel = inputs.self.nixosConfigurations.maestro.config.system.build.toplevel;
    maestroMenu = config.packages.maestro-menu;
    xenOrchestraCe = config.packages.xen-orchestra-ce;
    installerSystem = inputs.nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [./_source];
      specialArgs = {
        inherit applianceToplevel maestroMenu xenOrchestraCe;
        managementCIDRs = inputs.self.nixosConfigurations.maestro.config.maestro.operator.managementCIDRs;
      };
    };
    installerIso = assert builtins.elem applianceToplevel installerSystem.config.isoImage.storeContents;
    assert builtins.elem maestroMenu installerSystem.config.isoImage.storeContents;
    assert builtins.elem xenOrchestraCe installerSystem.config.isoImage.storeContents;
      installerSystem.config.system.build.isoImage;
    installerQualification = import ./_lib/qualification.nix {inherit lib installerSystem installerIso;};
  in {
    _module.args.installerQualification = installerQualification;
    packages.installer-iso = installerIso;
    packages.bootstrap = pkgs.callPackage ./_source/bootstrap-package/package.nix {};
  };
}
