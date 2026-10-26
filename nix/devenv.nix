{pkgs, ...}: let
  # GitHub checkouts are Git flakes and exclude ignored devenv state. jj
  # workspaces do not expose a .git directory, so they require an explicit
  # path reference instead of Nix's Git discovery.
  withFlake = command: ''
    flake_ref="path:$DEVENV_ROOT"
    if git -C "$DEVENV_ROOT" rev-parse --show-toplevel >/dev/null 2>&1; then
      flake_ref="git+file:$DEVENV_ROOT"
    fi
    ${command}
  '';

  runFlakePackage = package: arguments:
    withFlake ''
      MAESTRO_SYSTEM_ROOT="$DEVENV_ROOT" \
        nix run --accept-flake-config "$flake_ref#${package}" -- ${arguments}
    '';
in {
  packages = import ./devenv-packages.nix {inherit pkgs;};

  # Public pulls need no credentials. Publication is the explicit audited task
  # below, so ordinary hosted jobs cannot automatically push realized closures.
  cachix.pull = [
    "maestro"
    "xen-orchestra-ce"
    "nix-community"
  ];

  tasks = {
    "cache:doctor".exec = runFlakePackage "maestro-ci-cache-doctor" "";
    "ci:codeql:rust-toolchain".exec = runFlakePackage "maestro-ci-codeql-rust-toolchain" "";
    "ci:qualification:restore".exec = runFlakePackage "maestro-ci-qualification-restore" "";
    "ci:security:verify-native".exec = runFlakePackage "maestro-ci-security-native-check" "";
    "ci:distribution:restore".exec = runFlakePackage "maestro-ci-distribution-restore" "";
    "ci:decision:refresh".exec = runFlakePackage "maestro-ci-decision-refresh" "";
    "ci:decision:health".exec = runFlakePackage "maestro-ci-decision-health" "";
    "ci:consumer-probe".exec = runFlakePackage "maestro-ci-consumer-probe" "";
    "release:retain".exec = runFlakePackage "maestro-ci-release-retain" "";
    "release:inspect".exec = runFlakePackage "maestro-ci-publication-inspect" "";
    "release:journal".exec = runFlakePackage "maestro-ci-publication-journal" "";
    "release:diagnostics".exec = runFlakePackage "maestro-ci-publication-diagnostics" "";
    "release:reserve".exec = runFlakePackage "maestro-ci-release-reservation" "";
    "release:complete".exec = runFlakePackage "maestro-ci-release-completion" "";
    "release:assets".exec = runFlakePackage "maestro-ci-publication-assets" "";
    "ci:decision:download".exec = runFlakePackage "maestro-ci-decision-download" "";
    "ci:decision:candidate".exec = runFlakePackage "maestro-ci-decision-candidate" "";
    "ci:decision:admission".exec = runFlakePackage "maestro-ci-decision-admission" "";
    "ci:decision:publication".exec = runFlakePackage "maestro-ci-decision-publication" "";
    "ci:decision:readiness".exec = runFlakePackage "maestro-ci-decision-readiness" "";
    "ci:decision:reconcile".exec = runFlakePackage "maestro-ci-decision-reconcile" "";
    "ci:decision:check".exec = runFlakePackage "maestro-ci-decision-check" "";
    "ci:decision:recovery".exec = runFlakePackage "maestro-ci-decision-recovery" "";
    "ci:decision:handoff".exec = runFlakePackage "maestro-ci-decision-handoff" "";
    "ci:decision:event".exec = runFlakePackage "maestro-ci-decision-event" "";
    "ci:source-security".exec = runFlakePackage "maestro-ci-source-security" "";
    "ci:route".exec = runFlakePackage "maestro-ci-route" "";
    "ci:retained-evidence".exec = runFlakePackage "maestro-ci-decision-only" "";
    "ci:classify".exec = runFlakePackage "maestro-ci-classify" "";

    "ci:repository-audit:format" = {
      exec = withFlake ''
        cd "$DEVENV_ROOT"
        if git rev-parse --show-toplevel >/dev/null 2>&1; then
          mapfile -d $'\0' -t nix_files < <(git ls-files -z -- '*.nix')
        else
          # jj workspaces do not expose .git. Ignore generated environment
          # state while retaining a useful local formatting check.
          mapfile -d $'\0' -t nix_files < <(
            find . \( -path './.devenv' -o -path './.direnv' \) -prune \
              -o -type f -name '*.nix' -print0
          )
        fi
        system="$(nix eval --impure --raw --expr builtins.currentSystem)"
        nix run --accept-flake-config "$flake_ref#formatter.$system" -- \
          --check "''${nix_files[@]}"
      '';
      execIfModified = [
        "*.nix"
        "**/*.nix"
      ];
    };
    "ci:repository-audit:flake" = {
      exec = ''
        export MAESTRO_CI_AUDIT_MANIFEST="''${MAESTRO_CI_AUDIT_MANIFEST:-$DEVENV_STATE/maestro-validation.json}"
        ${runFlakePackage "maestro-ci-repository-audit" "--no-write-lock-file"}
      '';
      # Reuse is safe only for an identical checkout; every tracked source or
      # documentation change is allowed to invalidate the complete contract.
      execIfModified = ["."];
    };
    "ci:repository-audit" = {
      after = [
        "ci:repository-audit:flake"
        "ci:repository-audit:format"
      ];
    };

    "ci:cache-validation" = {
      after = ["ci:repository-audit"];
      exec = runFlakePackage "maestro-ci-cache-validation" ''
        "''${MAESTRO_CI_AUDIT_MANIFEST:-$DEVENV_STATE/maestro-validation.json}"
      '';
    };

    "ci:qualification:resolve".exec = runFlakePackage "maestro-ci-resolve-qualification" "";
    "ci:qualification:assemble".exec = runFlakePackage "maestro-ci-qualification-assets" "";
    "ci:qualification:sign-check".exec = runFlakePackage "maestro-ci-sign-check" "";
    "ci:qualification:boot-media".exec = runFlakePackage "maestro-ci-boot-media" ''
      "''${INSTALLER_ISO:-result-installer/iso/maestro-installer.iso}"
    '';
    "ci:publish".exec = runFlakePackage "maestro-ci-publish" "";
    "ci:security:scan".exec = runFlakePackage "maestro-ci-security-scan" "";
    "ci:security:inventory-preflight".exec = runFlakePackage "maestro-ci-security-inventory-preflight" "";
    "ci:security:inventory".exec = runFlakePackage "maestro-ci-security-inventory" ''
      "''${SECURITY_SYSTEM_SBOM:-maestro-system.cdx.json}" "''${SECURITY_XO_SBOM:-xen-orchestra-supply.cdx.json}"
    '';
    "ci:security:applicability".exec = runFlakePackage "maestro-ci-security-applicability" ''
      "''${SECURITY_OUTPUT:-security-report}/grype-findings.json" \
      "''${SECURITY_INVENTORY:-candidate}/maestro-system.cdx.json" \
      "''${SECURITY_OUTPUT:-security-report}/critical-applicability.json"
    '';
    "ci:security:latest".exec = runFlakePackage "maestro-ci-security-latest" "";
    "ci:security:policy-drift".exec = runFlakePackage "maestro-ci-policy-drift" "";
    "ci:packer:validate".exec = runFlakePackage "maestro-ci-packer-validate" "";
    "ci:verdict".exec = runFlakePackage "maestro-ci-verdict" "";

    "ci:admit-trusted".exec = runFlakePackage "maestro-ci-trusted-ci-admission" "";
    "automation:queue".exec = runFlakePackage "maestro-ci-queue" "";
    "automation:fix-hashes".exec = runFlakePackage "maestro-ci-fix-hashes" "";
    "automation:update-locks".exec = runFlakePackage "maestro-ci-update-locks" "";
    "automation:validate-locks".exec = runFlakePackage "maestro-ci-lock-validate" "";
    "automation:open-lock-update-pr".exec =
      runFlakePackage "maestro-ci-open-update-pr" "flake.lock devenv.lock";

    "release:request".exec = runFlakePackage "maestro-ci-release-request" "create";
    "release:signal".exec = runFlakePackage "maestro-ci-release-request" "signal";
    "release:pending".exec = runFlakePackage "maestro-ci-release-request" "pending";
    "release:continuation".exec = runFlakePackage "maestro-ci-release-request" "resolve";
    "release:prepare".exec = runFlakePackage "maestro-ci-release-manager" "prepare";
    "release:dispatch".exec = runFlakePackage "maestro-ci-release-manager" "dispatch";
    "release:inventory".exec = runFlakePackage "maestro-ci-release-manager" "inventory";
    "release:verify".exec = runFlakePackage "maestro-ci-release-manager" "verify";
    "release:attestations".exec = runFlakePackage "maestro-ci-release-attestations" "";
    "release:stage".exec = runFlakePackage "maestro-ci-release-manager" "stage";
    "release:draft".exec = runFlakePackage "maestro-ci-release-manager" "draft";
    "release:publish".exec = runFlakePackage "maestro-ci-release-manager" "publish";
    "release:advance".exec = runFlakePackage "maestro-ci-release-manager" "advance";
  };
}
