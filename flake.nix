{
  description = "Maestro - a focused Xen Orchestra appliance for XCP-ng";

  # GitHub Actions shares Nix build outputs through these public caches while
  # release artifacts remain immutable GitHub assets.
  nixConfig = {
    extra-substituters = [
      "https://install.determinate.systems"
      "https://devenv.cachix.org"
      "https://cachix.cachix.org"
      "https://maestro.cachix.org"
      "https://xen-orchestra-ce.cachix.org"
      "https://nix-community.cachix.org"
    ];
    extra-trusted-public-keys = [
      "cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM="
      "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw="
      "cachix.cachix.org-1:eWNHQldwUO7G2VkjpnjDbWwy4KQ/HNxht7H4SSoMckM="
      "maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0="
      "xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
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
    # Pin the reviewed XO runtime and shared admission evaluator together.
    xen-orchestra-ce.url = "github:closure-labs/xo-nixpkg/cc71a6c82674a26557271b5d4e730e2f05a8cf03";
  };
}
