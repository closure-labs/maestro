{...}: let
  inherit (import ../../development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "ci:boot:evidence".exec = runFlakePackage "maestro-ci-boot-evidence" "";
    "ci:build:installer".exec = runFlakePackage "maestro-ci-build-installer" "";
    "ci:qualification:restore".exec = runFlakePackage "maestro-ci-qualification-restore" "";
    "ci:qualification:resolve".exec = runFlakePackage "maestro-ci-resolve-qualification" "";
    "ci:qualification:assemble".exec = runFlakePackage "maestro-ci-qualification-assets" "";
    "ci:qualification:sign-check".exec = runFlakePackage "maestro-ci-sign-check" "";
    "ci:qualification:boot-media".exec = runFlakePackage "maestro-ci-boot-media" ''
      "''${INSTALLER_ISO:-result-installer/iso/maestro-installer.iso}"
    '';
  };
}
