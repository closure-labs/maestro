{lib, ...}: {
  perSystem = {config, ...}: {
    apps = {
      build-template = {
        type = "app";
        program = lib.getExe config.packages.build-template;
        meta.description = "Build a native Maestro XCP-ng template with Packer";
      };
      deploy-template = {
        type = "app";
        program = lib.getExe config.packages.deploy-template;
        meta.description = "Build and deploy a native Maestro XCP-ng template";
      };
    };
  };
}
