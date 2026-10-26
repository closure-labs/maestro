{...}: {
  perSystem = {pkgs, ...}: {
    formatter = pkgs.writeShellApplication {
      name = "maestro-format";
      runtimeInputs = [
        pkgs.alejandra
        pkgs.findutils
      ];
      text = ''
        if [ "$#" -gt 0 ]; then
          exec alejandra "$@"
        fi

        mapfile -d "" nix_files < <(find . -path ./.git -prune -o -type f -name "*.nix" -print0)
        if [ "''${#nix_files[@]}" -eq 0 ]; then
          exit 0
        fi

        exec alejandra "''${nix_files[@]}"
      '';
    };
  };
}
