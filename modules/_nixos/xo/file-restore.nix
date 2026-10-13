{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.maestro.xo;
  helper = pkgs.callPackage ../../../pkgs/maestro-file-restore/package.nix {inherit pkgs;};
in {
  options.maestro.xo.fileRestore.enable = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = "Restore guest files through a bounded unprivileged libguestfs appliance, with no host loop/LVM/filesystem mounts.";
  };
  config = lib.mkIf cfg.enable {
    systemd.services.xo-server.environment.XO_FILE_RESTORE_HELPER =
      if cfg.fileRestore.enable
      then lib.getExe helper
      else "/nonexistent/maestro-file-restore-disabled";
    # An explicitly disabled backend fails closed; it never reactivates XO's
    # legacy root/kernel restore implementation.
    maestro.xo.internal.fileRestorePackage = helper;
  };
  options.maestro.xo.internal.fileRestorePackage = lib.mkOption {
    type = lib.types.package;
    internal = true;
    readOnly = true;
  };
}
