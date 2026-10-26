{...}: {perSystem = {config, ...}: {checks = {inherit (config.packages) maestro-ci-repository-audit flake-plan-runner;};};}
