{...}: {
  perSystem = {
    pkgs,
    lib,
    ciNix,
    config,
    ...
  }: let
    graphSource = lib.fileset.toSource {
      root = ./_source;
      fileset = lib.fileset.unions [./_source/graph.py ./_source/bindings.py];
    };
  in {
    packages = {
      maestro-ci-graph = pkgs.writeShellApplication {
        name = "maestro-ci-graph";
        runtimeInputs = [pkgs.python3];
        text = ''
          export PYTHONDONTWRITEBYTECODE=1
          exec python3 ${graphSource}/graph.py "$@"
        '';
      };
      maestro-ci-graph-plan = pkgs.writeShellApplication {
        name = "maestro-ci-graph-plan";
        runtimeInputs = [pkgs.coreutils pkgs.diffutils pkgs.git pkgs.gnutar pkgs.jq ciNix config.packages.maestro-ci-route];
        text = ''
          export PATH=${lib.makeBinPath [pkgs.python3]}:"$PATH"
          maestro-ci-graph() { python3 ${graphSource}/graph.py "$@"; }
          ${builtins.readFile ./_source/plan.sh}
        '';
      };
    };
    checks.ci-graph-fixtures =
      pkgs.runCommandLocal "maestro-ci-graph-fixtures" {
        allowSubstitutes = true;
        nativeBuildInputs = [pkgs.python3 pkgs.bash pkgs.coreutils pkgs.jq pkgs.git pkgs.gnutar pkgs.diffutils pkgs.yq-go];
        source = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./_source/bindings.py
            ./_source/graph.py
            ./_source/plan.sh
            ./_source/result.py
            ./_source/transfer.py
            ./_source/summary.py
            ./_source/comparison.py
            ./_tests/test_graph.py
            ./_tests/test_plan.py
            ./_tests/test_results.py
            ./_tests/test_boot_downloads.py
            ./_tests/test_verdict.py
            ./_tests/test_signing.py
            ./_tests/test_summary.py
            ./_tests/test_comparison.py
          ];
        };
      } ''
        export PYTHONDONTWRITEBYTECODE=1
        export MAESTRO_VERDICT_SOURCE=${../checks/_source/verdict.sh}
        export MAESTRO_SIGNER_SOURCE=${../../features/installer/_source/sign-check.sh}
        export MAESTRO_CI_WORKFLOW=${../../../.github/workflows/ci.yml}
        export MAESTRO_BOOT_EVIDENCE_SOURCE=${../../features/installer/_source/boot-evidence.py}
        export MAESTRO_INVENTORY_VERIFIER_SOURCE=${../../features/installer/_source/verify-inventory.sh}
        export MAESTRO_BOOT_COMMAND_SOURCE=${../../features/installer/_source/boot-media.sh}
        python3 -m unittest discover -s "$source/_tests" -p 'test_*.py'
        ${lib.getExe config.packages.maestro-ci-job-transfer} --help >/dev/null
        touch "$out"
      '';
  };
}
