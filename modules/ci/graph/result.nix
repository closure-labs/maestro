{...}: {
  perSystem = {
    pkgs,
    lib,
    ...
  }: let
    source = lib.fileset.toSource {
      root = ./_source;
      fileset = lib.fileset.unions [./_source/bindings.py ./_source/result.py ./_source/comparison.py ./_source/graph.py ./_source/transfer.py ./_source/summary.py];
    };
  in {
    packages.maestro-ci-graph-result = pkgs.writeShellApplication {
      name = "maestro-ci-graph-result";
      runtimeInputs = [pkgs.python3];
      text = ''
        export PYTHONDONTWRITEBYTECODE=1
        export PYTHONPATH=${source}
        exec python3 ${source}/result.py
      '';
    };
  };
}
