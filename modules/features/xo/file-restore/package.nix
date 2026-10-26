{...}: {
  perSystem = {pkgs, ...}: {
    packages.maestro-file-restore = pkgs.callPackage ./_source/package.nix {};
  };
}
