{...}: {
  perSystem = {
    pkgs,
    ciNix,
    lib,
    ...
  }: let
    pythonSource = lib.fileset.toSource {
      root = ./_source;
      fileset = lib.fileset.unions [./_source/bindings.py ./_source/transfer.py];
    };
  in {
    packages.maestro-ci-job-transfer = pkgs.writeShellApplication {
      name = "maestro-ci-job-transfer";
      runtimeInputs = [pkgs.python3 ciNix];
      text = ''
        export PYTHONDONTWRITEBYTECODE=1
        export PYTHONPATH=${pythonSource}
        export MAESTRO_DECISION_CORE=${../authority/_source/decisions}
        export MAESTRO_DISTRIBUTION_CACHE_SOURCE=${./_source/distribution-cache.py}
        exec python3 ${./_source/transfer.py} "$@"
      '';
    };
  };
}
