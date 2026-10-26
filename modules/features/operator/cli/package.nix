{...}: {
  perSystem = {pkgs, ...}: {
    packages.maestroctl = pkgs.callPackage ./_source/package/package.nix {};
  };
}
