{...}: {
  perSystem = {
    pkgs,
    lib,
    ...
  }: {
    checks.xo-file-restore-fixtures =
      pkgs.runCommandLocal "maestro-file-restore-fixtures" {
        allowSubstitutes = true;
        nativeBuildInputs = [pkgs.python3];
        source = lib.fileset.toSource {
          root = ../../../..;
          fileset = lib.fileset.unions [./_source/restore.py ./_tests];
        };
      } ''
        export PYTHONDONTWRITEBYTECODE=1
        python3 "$source/modules/features/xo/file-restore/_tests/file-restore.py"
        touch "$out"
      '';
  };
}
