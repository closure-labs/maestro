{...}: {
  perSystem = {
    pkgs,
    ciNix,
    config,
    ...
  }: let
    packerXenserverPlugin = pkgs.callPackage ./_source/plugin/package.nix {};
    packerXenserver = pkgs.callPackage ./_source/packer/package.nix {inherit packerXenserverPlugin;};
    tools = pkgs.callPackage ./_source/tools/package.nix {
      inherit packerXenserver;
      nix = ciNix;
      qualificationValidation = [config.packages.maestro-ci-download-installer];
    };
  in {
    _module.args.packerXenserver = packerXenserver;
    packages.build-template = tools.build;
    packages.deploy-template = tools.deploy;
  };
}
