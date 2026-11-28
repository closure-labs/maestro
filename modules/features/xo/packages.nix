{...}: {
  perSystem = {system, ...}: let
    xoPackages = (import ./_lib/package-input.nix).packages.${system};
  in {
    packages = {
      xen-orchestra-ce = xoPackages.latest;
      xen-orchestra-supply-protector = xoPackages.supply-protector-latest;
      inherit (xoPackages) libvhdi;
      default = xoPackages.latest;
    };
  };
}
