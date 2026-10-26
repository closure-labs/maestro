{lib, ...}: {
  perSystem = {config, ...}: {
    apps.menu = {
      type = "app";
      program = lib.getExe config.packages.maestro-menu;
      meta.description = "Launch the Maestro SSH administration TUI";
    };
  };
}
