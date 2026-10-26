{...}: {perSystem = {config, ...}: {checks = {inherit (config.packages) build-template deploy-template;};};}
