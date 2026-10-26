{...}: {
  flake-file.nixConfig = {
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
}
