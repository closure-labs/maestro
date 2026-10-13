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
          export MAESTRO_CI_CLASSIFY_PATHS=${lib.getExe packages.maestro-ci-classify-paths}
          export MAESTRO_CI_VERDICT=${lib.getExe packages.maestro-ci-verdict}
          export MAESTRO_CI_LOCK_VALIDATE=${lib.getExe packages.maestro-ci-lock-validate}
          export MAESTRO_CI_ROUTE=${lib.getExe packages.maestro-ci-route}
          export MAESTRO_CI_RESOLVE_QUALIFICATION=${lib.getExe packages.maestro-ci-resolve-qualification}
          export MAESTRO_CI_RELEASE_MANAGER=${lib.getExe packages.maestro-ci-release-manager}
          export MAESTRO_CI_RELEASE_NOTES=${lib.getExe packages.maestro-ci-release-notes}
          export MAESTRO_CI_RELEASE_SPLIT=${lib.getExe packages.maestro-ci-release-stage}
          export MAESTRO_CI_RELEASE_VERSION=${lib.getExe packages.maestro-ci-release-version}
          export MAESTRO_CI_TRUSTED_UPDATE=${lib.getExe packages.maestro-ci-trusted-update}
          export MAESTRO_CI_VALIDATE_STATE=${lib.getExe packages.maestro-ci-validate-state}
          export MAESTRO_CI_TRUSTED_RUN=${lib.getExe packages.maestro-ci-trusted-run}
          export MAESTRO_CI_VERIFY_INVENTORY=${lib.getExe packages.maestro-ci-verify-inventory}
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
      in
        assert qualificationInputs.evidence.toplevel == inputs.self.nixosConfigurations.maestro.config.system.build.toplevel.outPath;
          pkgs.runCommandLocal "maestro-ci-plan-contract" {
            nativeBuildInputs = [pkgs.jq];
          } ''
            printf '%s\n' ${lib.escapeShellArg (builtins.toJSON plans)} > plans.json
            jq -e '
              (.validation.schemaVersion == 2) and
              (.validation.name == "maestro-validation") and
              (.validation.targets | length == 19) and
              (.media.schemaVersion == 2) and
              (.media.name == "maestro-media-qualification") and
              (.media.targets | length == 1) and
              (.evidence.schemaVersion == 2) and
              (.evidence.name == "maestro-evidence-qualification") and
              (.evidence.targets | length == 4) and
              (.publish.schemaVersion == 2) and
              (.publish.name == "maestro-publish") and
              (.publish.targets | length == 5)
            ' plans.json >/dev/null
            test -e ${qualificationInputs.media.source}/installer/default.nix
            test -e ${qualificationInputs.media.source}/modules/outputs/packages.nix
            ! test -e ${qualificationInputs.media.source}/docs
            ! test -e ${qualificationInputs.media.source}/.github
            touch "$out"
          '';

      eval-smoke = pkgs.runCommandLocal "maestro-eval-smoke" {} ''
        mkdir -p "$out"
        printf '%s\n' "Maestro appliance flake evaluation smoke check" > "$out/README"
      '';

      workflow-policy =
        pkgs.runCommandLocal "maestro-workflow-policy" {
          nativeBuildInputs = [
            pkgs.actionlint
            pkgs.bash
            pkgs.yq-go
            pkgs.zizmor
          ];
        } ''
          cp -R ${inputs.self} source
          cd source
          # actionlint 1.7.12 predates GitHub's organization queue extension.
          actionlint -ignore 'unexpected key "queue"' .github/workflows/*.yml
          zizmor .github
          while IFS= read -r action; do
            case "$action" in
              ./*) ;;
              *@????????????????????????????????????????) ;;
              *)
                printf 'Action is not pinned to a full commit: %s\n' "$action" >&2
                exit 1
                ;;
            esac
            case "$action" in
              ./* | actions/checkout@* | actions/upload-artifact@* | actions/download-artifact@* | actions/attest@* | actions/create-github-app-token@* | DeterminateSystems/determinate-nix-action@* | DeterminateSystems/flakehub-push@*) ;;
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
          if yq -r '.jobs[].steps[]?.run // ""' .github/workflows/*.yml |
            grep -v '^---$' |
            grep -Ev "^$|^nix run --accept-flake-config \.#devenv -- tasks run --option 'packages:pkgs!' [']['] ci:repository-audit$|^nix run --accept-flake-config \.#devenv -- tasks run --mode single --option 'packages:pkgs!' [']['] [a-z0-9:_-]+$"; then
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
            ci:route ci:classify ci:repository-audit ci:qualification:resolve \
            ci:qualification:assemble ci:qualification:boot-media ci:qualification:sign-check \
            ci:security:scan ci:security:latest ci:security:policy-drift ci:packer:validate \
            ci:publish ci:verdict automation:queue \
            automation:fix-hashes \
            automation:update-locks automation:validate-locks automation:open-lock-update-pr \
            release:prepare release:dispatch release:inventory release:verify \
            release:stage release:draft release:publish release:advance; do
            grep -Fq "\"$task\"" nix/devenv.nix
          done
          grep -Fq 'pkgs.check-jsonschema' nix/automation/default.nix
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
            tests/*.sh
          touch "$out"
        '';

      automation-fixtures = mkSourceCheck {
        name = "automation-fixtures";
        command = ''
          bash ./tests/ci-helpers.sh
          bash ./tests/fix-nix-hashes.sh
        '';
      };

      security-fixtures = mkSourceCheck {
        name = "security-fixtures";
        command = "PYTHONDONTWRITEBYTECODE=1 python3 ./tests/security-inventory.py && bash ./tests/policy-drift.sh && bash ./tests/security-contracts.sh && bash ./tests/security-scan.sh";
        nativeBuildInputs = fixtureInputs ++ [pkgs.openssh pkgs.python3];
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
        command = "bash ./tests/release-assets.sh";
      };

      secretspec-contract =
        pkgs.runCommandLocal "maestro-secretspec-contract" {
          nativeBuildInputs = [
            pkgs.jq
            packages.secretspec
          ];
        } ''
          export HOME="$TMPDIR/home"
          mkdir -p "$HOME"
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile github \
            --output github-schema.json
          jq -e '.required == ["CACHIX_CACHE_NAME"]' github-schema.json >/dev/null
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile github-publish \
            --output publish-schema.json
          jq -e \
            '.required == ["CACHIX_AUTH_TOKEN", "CACHIX_CACHE_NAME"]' \
            publish-schema.json >/dev/null
          touch "$out"
        '';

      operator-fixtures = mkSourceCheck {
        name = "operator-fixtures";
        command = "MAESTRO_SKIP_EVAL=1 bash ./tests/run.sh";
        nativeBuildInputs = fixtureInputs ++ [pkgs.yq-go pkgs.openssh pkgs.gh];
      };

      repository-policy = import ../../nix/checks/repository-policy.nix {
        inherit lib pkgs;
        source = inputs.self;
      };

      configuration = assert appliance.maestro.xo.enable;
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
      assert appliance.networking.firewall.allowedTCPPorts == [22 80 443];
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
