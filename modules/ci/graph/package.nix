{...}: {
  perSystem = {
    pkgs,
    lib,
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
        runtimeInputs = [pkgs.coreutils pkgs.git pkgs.gnutar pkgs.jq ciNix];
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
          fileset = lib.fileset.unions [./_source/graph.py ./_tests];
        };
      } ''
        export PYTHONDONTWRITEBYTECODE=1
        python3 "$source/_tests/test_graph.py"
        touch "$out"
      '';
  };
}
