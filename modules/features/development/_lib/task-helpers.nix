{}: let
  # GitHub checkouts are Git flakes and exclude ignored devenv state. jj
  # workspaces do not expose a .git directory, so they require an explicit
  # path reference instead of Nix's Git discovery.
  withFlake = command: ''
    flake_ref="path:$DEVENV_ROOT"
    if git -C "$DEVENV_ROOT" rev-parse --show-toplevel >/dev/null 2>&1; then
      flake_ref="git+file:$DEVENV_ROOT"
    fi
    ${command}
  '';

  runFlakePackage = package: arguments:
    withFlake ''
      MAESTRO_SYSTEM_ROOT="$DEVENV_ROOT" \
        nix run --accept-flake-config "$flake_ref#${package}" -- ${arguments}
    '';
in {inherit withFlake runFlakePackage;}
