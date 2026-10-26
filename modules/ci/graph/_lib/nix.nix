{pkgs}: let
  command = name:
    pkgs.writeShellApplication {
      inherit name;
      text =
        builtins.replaceStrings ["@fallback@"] ["${pkgs.nix}/bin"]
        (builtins.readFile ../_source/nix.sh);
    };
in
  pkgs.symlinkJoin {
    name = "maestro-ci-nix";
    paths = map command ["nix" "nix-store" "nix-env"];
  }
