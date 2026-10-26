{...}: {
  perSystem = {pkgs, ...}: {
    packages.maestro-menu = pkgs.callPackage ./_source/frontend/package.nix {};
  };
}
