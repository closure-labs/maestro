{
  description = "Maestro - a focused Xen Orchestra appliance for XCP-ng";

  # GitHub Actions shares Nix build outputs through these public caches while
  # release artifacts remain immutable GitHub assets.
  nixConfig = {
    extra-substituters = [
      "https://install.determinate.systems"
      "https://devenv.cachix.org"
      "https://cachix.cachix.org"
      "https://nixoa.cachix.org"
      "https://xen-orchestra-ce.cachix.org"
    ];
    extra-trusted-public-keys = [
      "cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM="
      "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw="
      "cachix.cachix.org-1:eWNHQldwUO7G2VkjpnjDbWwy4KQ/HNxht7H4SSoMckM="
      "nixoa.cachix.org-1:N+GsSSd2yKgj2hx01fMG6Oe7tLfbxEi/V0oZFEB721g="
      "xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E="
    ];
  };

  outputs = inputs:
    (
      inputs.nixpkgs.lib.evalModules {
        modules = [(inputs.import-tree ./modules)];
        specialArgs = {inherit inputs;};
      }
    ).config.flake;

  inputs = {
    den.url = "github:denful/den/v0.16.0";
    devenv.url = "github:cachix/devenv/v2.2.2";
    determinate.url = "https://flakehub.com/f/DeterminateSystems/determinate/*";
    # FlakeHub's /0 selectors track the latest stable release train. The /0.1
    # selectors are rolling and follow nixos-unstable.
    home-manager = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "https://flakehub.com/f/nix-community/home-manager/0";
    };
    import-tree.url = "github:vic/import-tree";
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0";
    xen-orchestra-ce.url = "git+https://github.com/closure-labs/xo-nixpkg.git?ref=refs/heads/main";
  };
}
