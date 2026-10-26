{...}: let
  inherit (import ../../../features/development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "ci:inventory:assets".exec = runFlakePackage "maestro-ci-inventory-assets" "";
  };
}
