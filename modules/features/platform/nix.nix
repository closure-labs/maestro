{...}: {
  den.aspects.platform.nixos =
    # SPDX-License-Identifier: Apache-2.0
    {
      inputs,
      lib,
      pkgs,
      ...
    }: let
      # Retain the official output for cache preflight/provenance; the installed
      # runtime below is rebuilt from the same source with appliance dependencies.
      upstreamDeterminateNix = inputs.determinate.inputs.nix.packages.${pkgs.stdenv.hostPlatform.system}.default;
      # Use the upstream public source-build interface with patched appliance
      # dependencies. This rebuilds the actual linked runtime, including Nix's
      # libarchive/OpenSSL consumers; changing a CLI package would not do that.
      determinateComponents = inputs.determinate.inputs.nix.lib.makeComponents {inherit pkgs;};
      patchedDeterminateNix = determinateComponents.nix-everything;
      determinateNix = pkgs.symlinkJoin {
        name = "determinate-nix-${upstreamDeterminateNix.version}";
        paths = [patchedDeterminateNix.out];
        passthru = {
          upstream = upstreamDeterminateNix;
          patched = patchedDeterminateNix;
          inherit (upstreamDeterminateNix) pname version;
        };
        meta =
          (upstreamDeterminateNix.meta or {})
          // {
            outputsToInstall = ["out"];
          };
      };
    in {
      imports = [inputs.determinate.nixosModules.default];

      nix = {
        package = lib.mkForce determinateNix;
        settings = {
          extra-substituters = [
            "https://install.determinate.systems"
            "https://maestro.cachix.org"
            "https://xen-orchestra-ce.cachix.org"
            "https://devenv.cachix.org"
            "https://nix-community.cachix.org"
          ];
          extra-trusted-public-keys = [
            "cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM="
            "maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0="
            "xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E="
            "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw="
            "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
          ];
          trusted-users = [
            "root"
            "@wheel"
          ];
        };
        gc = {
          automatic = true;
          dates = "weekly";
          options = "--delete-older-than 30d";
        };
      };
    };
}
