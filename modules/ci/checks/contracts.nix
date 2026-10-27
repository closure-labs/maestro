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
    appliance = inputs.self.nixosConfigurations.maestro.config;
    fixtureInputs = [
      pkgs.bash
      pkgs.coreutils
      pkgs.findutils
      pkgs.git
      pkgs.gnugrep
      pkgs.gnused
      pkgs.jq
    ];
    mkSourceCheck = import _lib/source-check.nix {inherit pkgs lib inputs packages fixtureInputs;};
  in {
    checks = {
      eval-smoke =
        pkgs.runCommandLocal "maestro-eval-smoke" {
          allowSubstitutes = true;
        } ''
          mkdir -p "$out"
          printf '%s\n' "Maestro appliance flake evaluation smoke check" > "$out/README"
        '';

      workflow-policy =
        pkgs.runCommandLocal "maestro-workflow-policy" {
          allowSubstitutes = true;
          nativeBuildInputs = [
            pkgs.python3
            pkgs.actionlint
            pkgs.bash
            pkgs.gnused
            pkgs.yq-go
            pkgs.zizmor
          ];
        } ''
          cp -R ${inputs.self} source
          # Older native linters predate GitHub's $/ syntax. Lint an
          # equivalent local-reference spelling for those parsers; enforce
          # immutable external actions and the protected local boundary below.
          cp -R source legacy-source
          chmod -R u+w legacy-source
          sed -i 's@^\([[:space:]]*\(- \)\?uses: \)\$/@\1./@' \
            legacy-source/.github/workflows/*.yml \
            legacy-source/.github/actions/*/action.yml
          (
            cd legacy-source
            # actionlint 1.7.12 predates the organization queue extension too.
            actionlint -ignore 'unexpected key "queue"' .github/workflows/*.yml
            ${lib.optionalString (lib.versionOlder pkgs.zizmor.version "1.29.0") "zizmor .github"}
          )
          cd source
          ${lib.optionalString (lib.versionAtLeast pkgs.zizmor.version "1.29.0") "zizmor .github"}
          while IFS= read -r action; do
            case "$action" in
              '$/'*) ;;
              './controller/.github/actions/setup-nix') ;;
              *@????????????????????????????????????????) ;;
              *)
                printf 'Action is not pinned to a full commit: %s\n' "$action" >&2
                exit 1
                ;;
            esac
            case "$action" in
              '$/'* | './controller/.github/actions/setup-nix' | actions/checkout@* | actions/upload-artifact@* | actions/download-artifact@* | actions/attest@* | actions/create-github-app-token@* | DeterminateSystems/determinate-nix-action@* | step-security/harden-runner@* | github/codeql-action/*@*) ;;
              *)
                printf 'Action is not an approved GitHub-platform boundary: %s\n' "$action" >&2
                exit 1
                ;;
            esac
          done < <(
            yq -r '.. | .uses? | select(. != null)' \
              .github/workflows/*.yml \
              .github/actions/*/action.yml |
              grep -v '^---$'
          )
          # This exact local action belongs only to the isolated protected
          # retained-evidence controller. All other actions remain pinned.
          for workflow in .github/workflows/*.yml; do
            owners=$(yq -r '.jobs | to_entries | .[] | select(.value.steps[].uses == "./controller/.github/actions/setup-nix") | .key' "$workflow")
            if [[ -n "$owners" && ( "$workflow" != .github/workflows/ci.yml || "$owners" != retained ) ]]; then
              printf 'Local controller setup is outside its protected job: %s\n' "$workflow" >&2
              exit 1
            fi
          done
          python3 modules/ci/authority/_source/decisions/signal_relay.py .github/workflows/decision-events.yml
          command_workflows=()
          for workflow in .github/workflows/*.yml; do
            if [[ $workflow != .github/workflows/decision-events.yml ]]; then
              command_workflows+=("$workflow")
            fi
          done
          if yq -r '.jobs[].steps[]?.run // ""' "''${command_workflows[@]}" |
            grep -v '^---$' |
            grep -Ev "^$|^nix run --accept-flake-config \.#devenv -- tasks run --option 'packages:pkgs!' [']['] ci:repository-audit$|^nix run --accept-flake-config \.#devenv -- tasks run --mode single --option 'packages:pkgs!' [']['] [a-z0-9:_-]+$|^nix run --accept-flake-config \.#devenv -- tasks run --mode single --show-output --option 'packages:pkgs!' [']['] (ci:decision:download|ci:decision:publication|release:inspect|ci:publish|release:journal|release:assets)$"; then
            printf 'Workflow command bypasses the declared devenv task graph.\n' >&2
            exit 1
          fi
          touch "$out"
        '';

      devenv-contract =
        pkgs.runCommandLocal "maestro-devenv-contract" {
          allowSubstitutes = true;
          nativeBuildInputs = [
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.jq
          ];
        } ''
          cd ${inputs.self}
          for task in \
            ci:route ci:classify ci:retained-evidence ci:repository-audit ci:qualification:resolve \
            ci:qualification:assemble ci:qualification:boot-media ci:qualification:sign-check \
            ci:security:scan ci:security:inventory-preflight ci:security:latest ci:security:policy-drift ci:packer:validate \
            ci:publish ci:cache-validation ci:verdict automation:queue \
            automation:fix-hashes \
            automation:update-locks automation:validate-locks automation:open-lock-update-pr \
            release:request release:signal release:pending release:continuation \
            release:prepare release:dispatch release:inventory release:verify \
            release:stage release:draft release:attestations release:publish release:advance; do
            grep -RFq --include=tasks.nix "\"$task\"" modules
          done
          grep -Fq 'pkgs.check-jsonschema' modules/ci/authority/_lib/common.nix
          # A cold runner must receive literal source patches with the cached
          # toolchain, even if coreutils's runtime output was substituted.
          for patch in ${lib.escapeShellArgs (map (patch: "${patch}") (builtins.filter builtins.isPath (pkgs.coreutils.patches or [])))}; do
            grep -Fx "$patch" ${pkgs.closureInfo {rootPaths = [packages.maestro-ci-toolchain];}}/store-paths
          done
          ! test -e modules/ci/authority/_source/cli.sh
          ! grep -Fq 'maestroCiCommand' modules/features/development/_lib/devenv.nix
          grep -Fq 'runFlakePackage "maestro-ci-route"' modules/ci/graph/_lib/tasks.nix
          grep -Fq 'runFlakePackage "maestro-ci-fix-hashes"' modules/features/development/_lib/tasks.nix
          grep -Fq 'runFlakePackage "maestro-ci-repository-audit"' modules/ci/checks/_lib/tasks.nix
          grep -Fq 'runFlakePackage "maestro-ci-verdict"' modules/ci/checks/_lib/tasks.nix
          grep -Fq 'runFlakePackage "maestro-ci-release-manager"' modules/release/publication/_lib/tasks.nix
          ! grep -RqE --exclude=contracts.nix 'ci:(prepare|plan|check|gate)|maestro-ci-(prepare|plan|check|gate|release)([^a-z-]|$)|MAESTRO_CI_(PREPARE|PLAN|CHECK|GATE|RELEASE)([^A-Z_]|$)|PREPARE_RESULT|PLAN_RESULT' \
            .github docs modules
          test "$(grep -c 'execIfModified = ' modules/ci/checks/_lib/tasks.nix)" -eq 2
          ! grep -Fq 'exec = "true";' modules/features/development/_lib/devenv.nix
          grep -Fq "git ls-files -z -- '*.nix'" modules/ci/checks/_lib/tasks.nix
          grep -Fq -- "-path './.devenv'" modules/ci/checks/_lib/tasks.nix
          grep -Fq 'DeterminateSystems/determinate-nix-action@61cbfe2efc2d4e7a8a6d56967c3c1058e846c858' \
            .github/actions/setup-nix/action.yml
          if grep -RqE '\.#maestro-ci([ -]|$)|\.#maestro-ci-(boot-media|qualification-assets|qualification-inputs|resolve-qualification|update-locks)' .github/workflows; then
            printf 'A hosted workflow bypasses the declared devenv task graph.\n' >&2
            exit 1
          fi
          ${lib.getExe packages.maestro-ci-lock-validate} \
            ${inputs.self}/flake.lock ${inputs.self}/devenv.lock
          # Release selection belongs to the existing input updater. Both
          # consumers retain exact locks without freezing the source URL.
          grep -Fq 'devenv.url = "github:cachix/devenv";' flake.nix
          grep -Fxq '    url: github:cachix/devenv' devenv.yaml
          for lock in flake.lock devenv.lock; do
            jq -e '.nodes[.nodes.root.inputs.devenv].original |
              .owner == "cachix" and .repo == "devenv" and
              (has("ref") | not) and (has("rev") | not)' "$lock" >/dev/null
          done
          touch "$out"
        '';

      shell-lint =
        pkgs.runCommandLocal "maestro-shell-lint" {
          allowSubstitutes = true;
          nativeBuildInputs = [
            pkgs.bash
            pkgs.shellcheck
            pkgs.findutils
          ];
        } ''
          cd ${inputs.self}
          mapfile -d "" -t shell_files < <(find modules .github -type f -name '*.sh' -print0)
          for shell_file in "''${shell_files[@]}"; do
            bash -n "$shell_file"
          done
          shellcheck "''${shell_files[@]}"
          touch "$out"
        '';

      automation-fixtures = mkSourceCheck {
        name = "automation-fixtures";
        nativeBuildInputs = fixtureInputs ++ [pkgs.python3 (import ../graph/_lib/nix.nix {inherit pkgs;})];
        command = ''
          bash ./modules/ci/graph/_tests/ci-helpers.sh
          bash ./modules/ci/checks/_tests/update-pr.sh
          bash ./modules/ci/graph/_tests/qualification-cache.sh
          bash ./modules/ci/checks/_tests/fix-nix-hashes.sh
          bash ./modules/ci/checks/_tests/ci-runtime-config.sh
          bash ./modules/ci/checks/_tests/cache-validation.sh
        '';
      };

      repository-policy = import ./_lib/repository-policy.nix {
        inherit lib pkgs;
        source = inputs.self;
      };

      source-security = mkSourceCheck {
        name = "source-security";
        command = "${lib.getExe packages.maestro-ci-source-security}";
        nativeBuildInputs = fixtureInputs ++ [packages.maestro-ci-source-security];
      };
    };
  };
}
