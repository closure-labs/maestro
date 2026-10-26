{config, ...}: {
  perSystem = {
    pkgs,
    lib,
    ciNix,
    ...
  }: let
    source = lib.fileset.toSource {
      root = ./_source;
      fileset = lib.fileset.unions [./_source/comparison.py ./_source/graph.py ./_source/transfer.py ./_source/summary.py];
    };
    command = operation:
      pkgs.writeShellApplication {
        name = "maestro-ci-graph-${operation}";
        runtimeInputs = [pkgs.python3 pkgs.git ciNix];
        text = ''
          export NIX_CONFIG="''${NIX_CONFIG:-}
          extra-substituters = ${lib.concatStringsSep " " config.flake-file.nixConfig.extra-substituters}
          extra-trusted-public-keys = ${lib.concatStringsSep " " config.flake-file.nixConfig.extra-trusted-public-keys}"
          export PYTHONDONTWRITEBYTECODE=1
          export PYTHONPATH=${source}
          exec python3 ${source}/comparison.py ${operation}
        '';
      };
  in {
    packages.maestro-ci-graph-reference = command "reference";
    packages.maestro-ci-graph-compare = command "compare";
  };
}
