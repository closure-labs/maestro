{...}: let
  inherit (import ../../development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "ci:build:appliance".exec = runFlakePackage "maestro-ci-build-appliance" "";
  };
}
