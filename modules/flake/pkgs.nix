{
  inputs,
  lib,
  ...
}: {
  perSystem = {
    system,
    pkgs,
    ...
  }: {
    _module.args.pkgs = import inputs.nixpkgs {
      inherit system;
      config.allowUnfreePredicate = package: lib.getName package == "packer";
    };
    _module.args.ciNix = import ../ci/graph/_lib/nix.nix {
      inherit pkgs;
    };
  };
}
