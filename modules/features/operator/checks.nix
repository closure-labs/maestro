{
  inputs,
  lib,
  ...
}: {
  perSystem = {
    pkgs,
    system,
    ...
  }: let
    packages = inputs.self.packages.${system};
    fixtureInputs = [
      pkgs.bash
      pkgs.coreutils
      pkgs.findutils
      pkgs.git
      pkgs.gnugrep
      pkgs.gnused
      pkgs.jq
    ];
    mkSourceCheck = import ../../ci/checks/_lib/source-check.nix {inherit pkgs lib inputs packages fixtureInputs;};
  in {
    checks = {
      operator-fixtures = mkSourceCheck {
        name = "operator-fixtures";
        exportCommands = false;
        source = lib.fileset.toSource {
          root = ../../..;
          fileset = lib.fileset.unions [
            ../.
            ../../../host
            ../../../.github
            ../../../.gitignore
            ../../../AGENTS.md
            ../../../VERSION
            ../../../flake.nix
            ../../../devenv.yaml
            ../../../devenv.local.yaml.example
            ../../ci/authority/_source/decision-check.sh
            ../../ci/authority/_source/decision-policy.json
            ../../ci/authority/_source/decision-candidate.py
            ../../ci/authority/_source/distribution-restore.py
            ../../ci/authority/_source/decisions/cache_publication.py
            ../../ci/authority/_source/queue.sh
            ../../ci/checks/_source/repository-audit.sh
            ../../ci/graph/_lib/plans.json
            ../../release/publication/_source/publication-assets.py
            ../../release/publication/_source/publish.sh
            ../../release/publication/_source/release-manager.sh
            ../../release/publication/_source/release-split.sh
          ];
        };
        command = "MAESTRO_SKIP_EVAL=1 bash ./modules/features/operator/_tests/run.sh";
        nativeBuildInputs = fixtureInputs ++ [pkgs.yq-go pkgs.openssh pkgs.gh (import ../../ci/graph/_lib/nix.nix {inherit pkgs;})];
      };
    };
  };
}
