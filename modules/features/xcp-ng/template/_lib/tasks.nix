{...}: let
  inherit (import ../../../development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "ci:packer:validate".exec = runFlakePackage "maestro-ci-packer-validate" "";
  };
}
