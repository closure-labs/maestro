{...}: {
  perSystem = {
    pkgs,
    lib,
    ...
  }: {
    checks.xo-storage-fixtures =
      pkgs.runCommandLocal "maestro-xo-storage-fixtures" {
        nativeBuildInputs = [pkgs.bash pkgs.coreutils pkgs.findutils pkgs.gawk pkgs.gnugrep pkgs.gnused pkgs.util-linux];
        source = lib.fileset.toSource {
          root = ../../..;
          fileset = lib.fileset.unions [./_source/storage-helper.sh ./_source/sudo-wrapper.sh ./_tests];
        };
      } ''
        bash "$source/modules/features/xo/_tests/xo-storage-helper.sh"
        touch "$out"
      '';
  };
}
