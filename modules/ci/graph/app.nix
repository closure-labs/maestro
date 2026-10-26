{lib, ...}: {
  perSystem = {config, ...}: {
    apps.run-ci-plan = {
      type = "app";
      program = lib.getExe config.packages.flake-plan-runner;
      meta.description = "Validate and execute a pure flake CI plan";
    };
  };
}
