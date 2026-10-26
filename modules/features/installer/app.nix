{lib, ...}: {
  perSystem = {config, ...}: {
    apps.bootstrap = {
      type = "app";
      program = lib.getExe config.packages.bootstrap;
      meta.description = "Bootstrap the fixed maestro appliance checkout";
    };
  };
}
