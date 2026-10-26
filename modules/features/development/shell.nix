{...}: {
  perSystem = {pkgs, ...}: {
    devShells.default = pkgs.mkShellNoCC {
      packages = import ./_lib/packages.nix {inherit pkgs;};
    };
  };
}
