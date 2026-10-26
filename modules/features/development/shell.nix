{...}: {
  perSystem = {pkgs, ...}: {
    devShells.default = pkgs.mkShellNoCC {
      packages = import ../../../nix/devenv-packages.nix {inherit pkgs;};
    };
  };
}
