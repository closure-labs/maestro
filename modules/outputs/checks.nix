{
  inputs,
  lib,
  ...
}: let
  systems = ["x86_64-linux"];
in {
  flake.checks = lib.genAttrs systems (
    system: let
      pkgs = inputs.nixpkgs.legacyPackages.${system};
      packages = inputs.self.packages.${system};
      appliance = inputs.self.nixosConfigurations.maestro.config;
      xoPackages = inputs.xen-orchestra-ce.packages.${system};
      managementCIDRType = inputs.self.nixosConfigurations.maestro.options.maestro.operator.managementCIDRs.type.nestedTypes.elemType;
      xoConfigFeatures = ["http" "redis" "remotes" "web"];
      xoConfigFragments = appliance.maestro.xo.internal.configFragments;
      fixtureInputs = [
        pkgs.bash
        pkgs.coreutils
        pkgs.findutils
        pkgs.git
        pkgs.gnugrep
        pkgs.gnused
        pkgs.jq
      ];
      mkSourceCheck = {
        name,
        command,
        nativeBuildInputs ? fixtureInputs,
      }:
        pkgs.runCommandLocal "maestro-${name}" {inherit nativeBuildInputs;} ''
          cp -R ${inputs.self} source
          chmod -R u+w source
          cd source
          export HOME="$TMPDIR/home"
          export MAESTRO_CI_BOOT_MEDIA=${lib.getExe packages.maestro-ci-boot-media}
          export MAESTRO_CI_QUALIFICATION_INPUTS=${lib.getExe packages.maestro-ci-qualification-inputs}
          export MAESTRO_CI_CLASSIFY=${lib.getExe packages.maestro-ci-classify}
          export MAESTRO_CI_CACHE_VALIDATION=${lib.getExe packages.maestro-ci-cache-validation}
          export MAESTRO_CI_CLASSIFY_PATHS=${lib.getExe packages.maestro-ci-classify-paths}
          export MAESTRO_CI_VERDICT=${lib.getExe packages.maestro-ci-verdict}
          export MAESTRO_CI_LOCK_VALIDATE=${lib.getExe packages.maestro-ci-lock-validate}
          export MAESTRO_CI_ROUTE=${lib.getExe packages.maestro-ci-route}
          export MAESTRO_CI_RESOLVE_QUALIFICATION=${lib.getExe packages.maestro-ci-resolve-qualification}
          export MAESTRO_CI_RELEASE_MANAGER=${lib.getExe packages.maestro-ci-release-manager}
          export MAESTRO_CI_RELEASE_ATTESTATIONS=${lib.getExe packages.maestro-ci-release-attestations}
          export MAESTRO_CI_RELEASE_NOTES=${lib.getExe packages.maestro-ci-release-notes}
          export MAESTRO_CI_RELEASE_SPLIT=${lib.getExe packages.maestro-ci-release-stage}
          export MAESTRO_CI_RELEASE_VERSION=${lib.getExe packages.maestro-ci-release-version}
          export MAESTRO_CI_TRUSTED_UPDATE=${lib.getExe packages.maestro-ci-trusted-update}
          export MAESTRO_CI_OPEN_UPDATE_PR=${lib.getExe packages.maestro-ci-open-update-pr}
          export MAESTRO_CI_QUALIFICATION_CACHE=${lib.getExe packages.maestro-ci-qualification-cache}
          export MAESTRO_CI_VALIDATE_STATE=${lib.getExe packages.maestro-ci-validate-state}
          export MAESTRO_CI_TRUSTED_RUN=${lib.getExe packages.maestro-ci-trusted-run}
          export MAESTRO_CI_VERIFY_INVENTORY=${lib.getExe packages.maestro-ci-verify-inventory}
          export MAESTRO_CI_VERIFY_STATE=${lib.getExe packages.maestro-ci-verify-state}
          export MAESTRO_CI_DOWNLOAD_INSTALLER=${lib.getExe packages.maestro-ci-download-installer}
          export MAESTRO_CI_SECURITY_SCAN=${lib.getExe packages.maestro-ci-security-scan}
          export MAESTRO_CI_SECURITY_VERDICT=${lib.getExe packages.maestro-ci-security-verdict}
          export MAESTRO_SYSTEM_ROOT="$PWD"
          mkdir -p "$HOME"
          ${command}
          touch "$out"
        '';
    in {
      inherit
        (packages)
        bootstrap
        build-template
        deploy-template
        flake-plan-runner
        metadata
        maestro-ci-repository-audit
        maestroctl
        ;

      ci-plan-contract = let
        plans = inputs.self.lib.ciPlans.${system};
        qualificationInputs = inputs.self.lib.ciQualificationInputs.${system};
        unsupportedInstaller = initrd:
          builtins.tryEval (import ./_installer-qualification.nix {
            inherit lib;
            installerIso = null;
            installerSystem = {
              inherit pkgs;
              config = {
                boot = {inherit initrd;};
                specialisation = {};
              };
            };
          });
      in
        assert !(unsupportedInstaller {
          systemd.enable = false;
          prepend = [];
        }).success;
        assert !(unsupportedInstaller {
          systemd.enable = true;
          prepend = ["unattributed-archive"];
        }).success;
        assert builtins.length plans.publish.targets == 7;
        assert builtins.attrNames inputs.self.nixosConfigurations == ["maestro"];
        assert packages.distribution-inventory.qualification.system != appliance.system.build.toplevel.outPath;
        assert builtins.all (binding: builtins.elem binding.root (builtins.attrValues packages.distribution-inventory.qualification.roots)) packages.distribution-inventory.qualification.bindings;
        assert qualificationInputs.evidence.toplevel == inputs.self.nixosConfigurations.maestro.config.system.build.toplevel.outPath;
        assert qualificationInputs.media.dependencies.installerIso == packages.installer-iso.outPath;
        assert !(qualificationInputs.media ? source);
          pkgs.runCommandLocal "maestro-ci-plan-contract" {
            nativeBuildInputs = [pkgs.jq];
          } ''
            printf '%s\n' ${lib.escapeShellArg (builtins.toJSON plans)} > plans.json
            jq -e '
              (.validation.schemaVersion == 2) and
              (.validation.name == "maestro-validation") and
              (.validation.targets | length == 20) and
              (.media.schemaVersion == 2) and
              (.media.name == "maestro-media-qualification") and
              (.media.targets | length == 1) and
              (.evidence.schemaVersion == 2) and
              (.evidence.name == "maestro-evidence-qualification") and
              (.evidence.targets | length == 5) and
              (.publish.schemaVersion == 2) and
              (.publish.name == "maestro-publish") and
              (.publish.targets | length == 7)
            ' plans.json >/dev/null
            touch "$out"
          '';

      sbomnix-runtime =
        pkgs.runCommandLocal "maestro-sbomnix-runtime" {
          nativeBuildInputs = fixtureInputs;
        } ''
          export MAESTRO_SBOMNIX=${lib.getExe packages.sbomnix}
          bash ${../../tests/sbomnix-runtime.sh}
          bash ${../../tests/sbomnix-lock-root.sh}
          touch "$out"
        '';

      eval-smoke = pkgs.runCommandLocal "maestro-eval-smoke" {} ''
        mkdir -p "$out"
        printf '%s\n' "Maestro appliance flake evaluation smoke check" > "$out/README"
      '';

      workflow-policy =
        pkgs.runCommandLocal "maestro-workflow-policy" {
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
          python3 nix/automation/decisions/signal_relay.py .github/workflows/decision-events.yml
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
            grep -Fq "\"$task\"" nix/devenv.nix
          done
          grep -Fq 'pkgs.check-jsonschema' nix/automation/default.nix
          # A cold runner must receive literal source patches with the cached
          # toolchain, even if coreutils's runtime output was substituted.
          for patch in ${lib.escapeShellArgs (map (patch: "${patch}") (builtins.filter builtins.isPath (pkgs.coreutils.patches or [])))}; do
            grep -Fx "$patch" ${pkgs.closureInfo {rootPaths = [packages.maestro-ci-toolchain];}}/store-paths
          done
          ! test -e nix/automation/cli.sh
          ! grep -Fq 'maestroCiCommand' nix/devenv.nix
          grep -Fq 'runFlakePackage "maestro-ci-route"' nix/devenv.nix
          grep -Fq 'runFlakePackage "maestro-ci-fix-hashes"' nix/devenv.nix
          grep -Fq 'runFlakePackage "maestro-ci-repository-audit"' nix/devenv.nix
          grep -Fq 'runFlakePackage "maestro-ci-verdict"' nix/devenv.nix
          grep -Fq 'runFlakePackage "maestro-ci-release-manager"' nix/devenv.nix
          ! grep -RqE --exclude=checks.nix 'ci:(prepare|plan|check|gate)|maestro-ci-(prepare|plan|check|gate|release)([^a-z-]|$)|MAESTRO_CI_(PREPARE|PLAN|CHECK|GATE|RELEASE)([^A-Z_]|$)|PREPARE_RESULT|PLAN_RESULT' \
            .github nix docs modules tests
          test "$(grep -c 'execIfModified = ' nix/devenv.nix)" -eq 2
          ! grep -Fq 'exec = "true";' nix/devenv.nix
          grep -Fq "git ls-files -z -- '*.nix'" nix/devenv.nix
          grep -Fq -- "-path './.devenv'" nix/devenv.nix
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
          nativeBuildInputs = [
            pkgs.shellcheck
          ];
        } ''
          cd ${inputs.self}
          shellcheck \
            installer/*.sh \
            modules/_nixos/xo/*.sh \
            packer/*.sh \
            packer/scripts/*.sh \
            scripts/*.sh \
            scripts/lib/*.sh \
            scripts/tui/*.sh \
            nix/automation/*.sh \
            nix/ci-nix.sh \
            .github/actions/setup-nix/*.sh \
            tests/*.sh
          touch "$out"
        '';

      automation-fixtures = mkSourceCheck {
        name = "automation-fixtures";
        nativeBuildInputs = fixtureInputs ++ [pkgs.python3 (import ../../nix/ci-nix.nix {inherit pkgs;})];
        command = ''
          bash ./tests/ci-helpers.sh
          bash ./tests/update-pr.sh
          bash ./tests/qualification-cache.sh
          bash ./tests/fix-nix-hashes.sh
          bash ./tests/ci-runtime-config.sh
          bash ./tests/cache-validation.sh
        '';
      };

      source-security = mkSourceCheck {
        name = "source-security";
        command = "${lib.getExe packages.maestro-ci-source-security}";
        nativeBuildInputs = fixtureInputs ++ [packages.maestro-ci-source-security];
      };

      security-fixtures = mkSourceCheck {
        name = "security-fixtures";
        command = ''
          PYTHONDONTWRITEBYTECODE=1 python3 ./tests/security-inventory.py
          PYTHONDONTWRITEBYTECODE=1 python3 ./tests/security-components.py
          PYTHONDONTWRITEBYTECODE=1 python3 ./tests/file-restore.py
          bash ./tests/policy-drift.sh
          bash ./tests/security-contracts.sh
          bash ./tests/evidence-download.sh
          bash ./tests/provenance-requests.sh
          bash ./tests/security-scan.sh
          bash ./tests/codeql-rust-toolchain.sh ${lib.getExe packages.maestro-ci-codeql-rust-toolchain}
          PYTHONDONTWRITEBYTECODE=1 python3 tests/decision-observations.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_secret_inventory.py
          PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/decisions -p '*.py'
          MAESTRO_TEST_PUBLISH_COMMAND=${lib.getExe packages.maestro-ci-publish} \
            MAESTRO_TEST_INSPECT_COMMAND=${lib.getExe packages.maestro-ci-publication-inspect} \
            PYTHONDONTWRITEBYTECODE=1 python3 tests/test_publish_readback.py
          MAESTRO_TEST_PUBLISH_COMMAND=${lib.getExe packages.maestro-ci-publish} \
            MAESTRO_TEST_INSPECT_COMMAND=${lib.getExe packages.maestro-ci-publication-inspect} \
            PYTHONDONTWRITEBYTECODE=1 python3 tests/test_readonly_preflight.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_cache_cancellation.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_cache_recovery.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_scheduling.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_operations.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_consumer_probe.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_consumer_result.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/publication-journal.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_release_transaction.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_ci_admission.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/publication-diagnostics.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/test_request_attribution.py
          MAESTRO_TEST_LIBCURL=${pkgs.curl.out}/lib/libcurl.so.4 \
            MAESTRO_TEST_CURL=${pkgs.curl.bin}/bin/curl \
            MAESTRO_TEST_OPENSSL=${pkgs.openssl.bin}/bin/openssl \
            PYTHONDONTWRITEBYTECODE=1 python3 tests/test_public_cache_transport.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/distribution-cache.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/qualification-restore.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/installer-coverage.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/decision-operations.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/decision-only.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/audit-diagnostics.py
          PYTHONDONTWRITEBYTECODE=1 python3 tests/qualification-diagnostics.py
        '';
        nativeBuildInputs = fixtureInputs ++ [pkgs.openssh pkgs.python3 pkgs.gitleaks pkgs.yq-go];
      };

      packer-policy = mkSourceCheck {
        name = "packer-policy";
        command = "${lib.getExe packages.maestro-ci-packer-validate}";
      };

      qualification-input-fixtures = mkSourceCheck {
        name = "qualification-input-fixtures";
        command = "bash ./tests/qualification-inputs.sh";
      };

      release-fixtures = mkSourceCheck {
        name = "release-fixtures";
        command = ''
          bash ./tests/release-assets.sh
          bash ./tests/release-attestations.sh
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 tests/release-request.py
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 tests/release-graph.py
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 tests/pilot-benchmark.py
        '';
        nativeBuildInputs = fixtureInputs ++ [pkgs.yq-go];
      };

      secretspec-contract =
        pkgs.runCommandLocal "maestro-secretspec-contract" {
          nativeBuildInputs = [
            pkgs.jq
            pkgs.python3
            packages.secretspec
          ];
        } ''
          export HOME="$TMPDIR/home"
          mkdir -p "$HOME"
          SECRETSPEC_BIN=${inputs.devenv.packages.${system}.devenv}/bin/secretspec \
            PYTHONDONTWRITEBYTECODE=1 python3 ${inputs.self}/tests/test_cache_doctor.py
          secretspec schema --file ${inputs.self}/secretspec.toml \
            --profile development --output development-schema.json
          jq -e '[.properties | keys[] | select(test("TOKEN|PASSWORD|PEM|DECIDER_KEY"))] == []' \
            development-schema.json >/dev/null
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile github \
            --output github-schema.json
          jq -e '.required == ["CACHIX_MAESTRO_PUBKEY", "MAESTRO_DECISION_ONLY_REUSE_ENABLED", "MAESTRO_PACKET_METADATA_BATCH_ENABLED", "MAESTRO_PACKET_METADATA_REUSE_ENABLED", "MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED", "MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED", "MAESTRO_RELEASE_CONTINUATION_ENABLED", "MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS", "MAESTRO_RELEASE_TRANSACTION_ENABLED", "MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED"]' github-schema.json >/dev/null
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile github-queue \
            --output queue-schema.json
          jq -e '.required == ["CACHIX_MAESTRO_PUBKEY", "MAESTRO_DECISION_ONLY_REUSE_ENABLED", "MAESTRO_PACKET_METADATA_BATCH_ENABLED", "MAESTRO_PACKET_METADATA_REUSE_ENABLED", "MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED", "MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED", "MAESTRO_RELEASE_CONTINUATION_ENABLED", "MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS", "MAESTRO_RELEASE_TRANSACTION_ENABLED", "MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED", "MERGE_QUEUE_TOKEN"]' queue-schema.json >/dev/null
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile github-publish \
            --output publish-schema.json
          jq -e \
            '.required == ["CACHIX_MAESTRO_AUTH_TOKEN", "CACHIX_MAESTRO_PUBKEY", "MAESTRO_DECISION_ONLY_REUSE_ENABLED", "MAESTRO_PACKET_METADATA_BATCH_ENABLED", "MAESTRO_PACKET_METADATA_REUSE_ENABLED", "MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED", "MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED", "MAESTRO_RELEASE_CONTINUATION_ENABLED", "MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS", "MAESTRO_RELEASE_TRANSACTION_ENABLED", "MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED"]' \
            publish-schema.json >/dev/null
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile local-publish \
            --output local-schema.json
          jq -e \
            '.required == ["CACHIX_MAESTRO_AUTH_TOKEN", "CACHIX_MAESTRO_PUBKEY", "MAESTRO_DECISION_ONLY_REUSE_ENABLED", "MAESTRO_PACKET_METADATA_BATCH_ENABLED", "MAESTRO_PACKET_METADATA_REUSE_ENABLED", "MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED", "MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED", "MAESTRO_RELEASE_CONTINUATION_ENABLED", "MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS", "MAESTRO_RELEASE_TRANSACTION_ENABLED", "MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED"]' \
            local-schema.json >/dev/null
          touch "$out"
        '';

      operator-fixtures = mkSourceCheck {
        name = "operator-fixtures";
        command = "MAESTRO_SKIP_EVAL=1 bash ./tests/run.sh";
        nativeBuildInputs = fixtureInputs ++ [pkgs.yq-go pkgs.openssh pkgs.gh (import ../../nix/ci-nix.nix {inherit pkgs;})];
      };

      repository-policy = import ../../nix/checks/repository-policy.nix {
        inherit lib pkgs;
        source = inputs.self;
      };

      configuration = assert inputs.self.lib.ciQualificationInputs.${system}.media.dependencies.applianceToplevel == appliance.system.build.toplevel.outPath;
      assert appliance.maestro.xo.enable;
      assert appliance.maestro.xo.channel == "latest";
      assert lib.all (channel: builtins.hasAttr channel xoPackages) ["latest" "stable" "rolling"];
      assert appliance.maestro.xo.package == xoPackages.latest;
      assert builtins.attrNames xoConfigFragments == xoConfigFeatures;
      assert lib.all (
        feature: builtins.hasAttr "xo-server/config.nixos-${feature}.toml" appliance.environment.etc
      )
      xoConfigFeatures;
      assert xoConfigFragments.redis.redis.socket == "/run/redis-xo/redis.sock";
      assert xoConfigFragments.remotes.remoteOptions.mountsDir == appliance.maestro.xo.storage.mountsDir;
      assert xoConfigFragments.remotes.remoteOptions.useSudo;
      assert xoConfigFragments.http.http.redirectToHttps == appliance.maestro.xo.tls.enable;
      assert builtins.length xoConfigFragments.http.http.listen == 2;
      assert xoConfigFragments.web.http.mounts."/v6" == "${appliance.maestro.xo.home}/xen-orchestra/@xen-orchestra/web/dist";
      assert appliance.systemd.services.xo-server.environment.TMPDIR == appliance.maestro.xo.tempDir;
      assert appliance.maestro.xo.fileRestore.enable;
      assert appliance.systemd.services.xo-server.environment.XO_FILE_RESTORE_HELPER == lib.getExe appliance.maestro.xo.internal.fileRestorePackage;
      assert appliance.maestro.xo.storage.libvhdiPackage == inputs.xen-orchestra-ce.packages.x86_64-linux.libvhdi;
      assert appliance.programs.fuse.userAllowOther;
      assert builtins.elem "fuse" appliance.users.users.${appliance.maestro.xo.user}.extraGroups;
      assert appliance.services.redis.servers.xo.enable;
      assert appliance.systemd.services ? xo-autocert;
      assert appliance.maestro.xo.internal.sudoWrapper != null;
      assert builtins.elem "multi-user.target" appliance.systemd.services.xen-guest-agent.wantedBy;
      assert appliance.services.cloud-init.enable;
      assert !appliance.services.cloud-init.network.enable;
      assert appliance.services.cloud-init.settings.datasource_list == ["NoCloud" "None"];
      assert appliance.services.cloud-init.settings.system_info.default_user.name == "maestro";
      assert appliance.services.cloud-init.settings.cloud_init_modules
      == [
        "seed_random"
        "growpart"
        "resizefs"
      ];
      assert appliance.services.cloud-init.settings.growpart.devices == ["/"];
      assert appliance.services.cloud-init.settings.resize_rootfs;
      assert appliance.services.cloud-init.settings.network.config == "disabled";
      assert appliance.services.cloud-init.settings.disable_network_activation;
      assert appliance.services.cloud-init.settings.ssh_genkeytypes == [];
      assert !appliance.services.cloud-init.settings.ssh.emit_keys_to_console;
      assert appliance.security.polkit.enable;
      assert builtins.elem pkgs.cloud-init appliance.environment.systemPackages;
      assert builtins.elem "cloud-config.service" appliance.systemd.services.sshd.after;
      assert appliance.services.openssh.settings.AllowUsers == ["maestro"];
      assert appliance.services.openssh.settings.PermitRootLogin == "no";
      assert !appliance.services.openssh.settings.PasswordAuthentication;
      assert !appliance.services.openssh.settings.KbdInteractiveAuthentication;
      assert appliance.users.users.xo.isSystemUser;
      assert appliance.users.users.xo.shell == "${pkgs.shadow}/bin/nologin";
      assert appliance.services.redis.servers.xo.settings.port == 0;
      assert appliance.services.redis.servers.xo.unixSocketPerm == 770;
      assert appliance.systemd.services.xo-server.serviceConfig.User == "xo";
      assert appliance.systemd.services.xo-server.serviceConfig.ProtectHome;
      assert appliance.systemd.services.xo-server.serviceConfig.ProtectSystem == "full";
      assert appliance.systemd.services.xo-server.serviceConfig.AmbientCapabilities == ["CAP_NET_BIND_SERVICE"];
      assert appliance.systemd.services.xo-server.serviceConfig.EnvironmentFile == [];
      assert lib.all (rule: !(builtins.elem "xo" rule.users) || lib.all (command: lib.hasSuffix "/bin/xo-storage-helper" command.command) rule.commands) appliance.security.sudo.extraRules;
      assert appliance.networking.firewall.allowedTCPPorts == [];
      assert appliance.maestro.operator.managementCIDRs == ["0.0.0.0/0" "::/0"];
      assert lib.all managementCIDRType.check ["0.0.0.0/0" "::/0" "192.168.98.0/24" "2001:db8::1/128"];
      assert lib.all (cidr: !managementCIDRType.check cidr) ["0.0.0.0" "256.0.0.0/8" "192.168.0.0/33" "::/129" "2001:::1/64" "12345::/64" "::/0;accept"];
      assert !appliance.services.openssh.openFirewall;
      assert appliance.networking.firewall.allowedUDPPorts == [];
      assert !appliance.services.avahi.enable;
      assert !appliance.services.samba.enable;
      assert !appliance.hardware.bluetooth.enable;
      assert !appliance.virtualisation.libvirtd.enable;
      assert !appliance.services.nfs.server.enable;
      assert appliance.determinate.enable;
      assert appliance.home-manager.users.maestro.programs.git.enable;
      assert appliance.nix.gc.automatic;
      assert appliance.boot.loader.systemd-boot.configurationLimit == 10;
        pkgs.runCommandLocal "maestro-configuration-assertions" {} ''
          touch "$out"
        '';

      runtime-security = import ../../nix/tests/runtime-security.nix {inherit pkgs inputs appliance;};
    }
  );
}
