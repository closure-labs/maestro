{
  inputs,
  lib,
  ...
}: {
  perSystem = {system, ...}: {
    _module.args.pkgs = import inputs.nixpkgs {
      inherit system;
      config.allowUnfreePredicate = package: lib.getName package == "packer";
    };
    _module.args.ciNix = import ../../nix/ci-nix.nix {
      pkgs = import inputs.nixpkgs {inherit system;};
    };
  };
}
