{...}: {
  perSystem = {
    pkgs,
    lib,
    ciNix,
    ...
  }: {
    packages = {
      maestro-ci-graph = pkgs.writeShellApplication {
        name = "maestro-ci-graph";
        runtimeInputs = [pkgs.python3];
        text = ''
          export PYTHONDONTWRITEBYTECODE=1
          exec python3 ${./_source/graph.py} "$@"
        '';
      };
      maestro-ci-graph-plan = pkgs.writeShellApplication {
        name = "maestro-ci-graph-plan";
        runtimeInputs = [pkgs.coreutils pkgs.diffutils pkgs.git pkgs.gnutar pkgs.jq ciNix];
        text = ''
          export PATH=${lib.makeBinPath [pkgs.python3]}:"$PATH"
          maestro-ci-graph() { python3 ${./_source/graph.py} "$@"; }
          ${builtins.readFile ./_source/plan.sh}
        '';
      };
    };
    checks.ci-graph-fixtures =
      pkgs.runCommandLocal "maestro-ci-graph-fixtures" {
        nativeBuildInputs = [pkgs.python3];
        source = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [./_source ./_tests/test_graph.py ./_tests/test_results.py ./_tests/test_verdict.py];
        };
      } ''
        export PYTHONDONTWRITEBYTECODE=1
        export MAESTRO_VERDICT_SOURCE=${../checks/_source/verdict.sh}
        python3 -m unittest discover -s "$source/_tests" -p 'test_*.py'
        touch "$out"
      '';
  };
}
