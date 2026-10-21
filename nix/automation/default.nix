{
  planRunner,
  packerXenserver,
  pkgs,
  ciNix,
  appliance,
  lockFile,
  packageSourceRoots,
  applicabilityCommand,
  distributionRoots,
  installerQualification,
}: let
  mkCommand = {
    name,
    prefix ? "",
    runtimeInputs ? [],
    source,
  }:
    pkgs.writeShellApplication {
      inherit runtimeInputs;
      name = "maestro-ci-${name}";
      text = builtins.readFile ./command-preamble.sh + prefix + builtins.readFile source;
    };

  boundedGh = pkgs.writeShellApplication {
    name = "gh";
    runtimeInputs = [pkgs.python3];
    text =
      builtins.replaceStrings
      ["@GH@" "@PYTHON@" "@OPERATIONS@"]
      ["${pkgs.gh}/bin/gh" "${pkgs.python3}/bin/python3" "${./decisions/operations.py}"]
      (builtins.readFile ./bounded-gh.sh);
  };

  commonInputs = with pkgs; [
    bash
    coreutils
    findutils
    git
    boundedGh
    gnugrep
    gnused
    jq
    ciNix
  ];

  spdxSchema = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json";
    hash = "sha256-I5IIt6woezz12amvI/nWmGOXEQKl4Vh6J6OYtDSQuJs=";
  };

  validatePlan = mkCommand {
    name = "validate-plan";
    prefix = ''
      MAESTRO_CI_PLAN_SCHEMA="''${MAESTRO_CI_PLAN_SCHEMA:-${./qualification-plan.schema.json}}"
      export MAESTRO_CI_PLAN_SCHEMA
    '';
    runtimeInputs = commonInputs ++ [pkgs.check-jsonschema];
    source = ./validate-plan.sh;
  };

  classifyPaths = mkCommand {
    name = "classify-paths";
    runtimeInputs = commonInputs;
    source = ./classify-paths.sh;
  };

  commands = {
    codeql-rust-toolchain = let
      toolchain = pkgs.runCommand "maestro-codeql-rust-toolchain" {} ''
        mkdir -p "$out/bin" "$out/lib/rustlib/src/rust"
        ln -s ${pkgs.cargo}/bin/cargo "$out/bin/cargo"
        ln -s ${pkgs.rustc}/bin/rustc "$out/bin/rustc"
        ln -s ${pkgs.rustc}/bin/rustdoc "$out/bin/rustdoc"
        ln -s ${pkgs.rustPlatform.rustLibSrc} "$out/lib/rustlib/src/rust/library"
      '';
    in
      mkCommand {
        name = "codeql-rust-toolchain";
        prefix = ''
          MAESTRO_CODEQL_RUST_TOOLCHAIN=${toolchain}
          MAESTRO_CODEQL_RUSTUP=${pkgs.rustup}/bin/rustup
          MAESTRO_CODEQL_RUST_SRC=${pkgs.rustPlatform.rustLibSrc}
          export MAESTRO_CODEQL_RUST_TOOLCHAIN MAESTRO_CODEQL_RUSTUP MAESTRO_CODEQL_RUST_SRC
        '';
        runtimeInputs = commonInputs ++ [pkgs.rustup];
        source = ./codeql-rust-toolchain.sh;
      };
    qualification-restore = mkCommand {
      name = "qualification-restore";
      prefix = ''
        MAESTRO_DECISION_CORE=${./decisions}
        export PYTHONPATH=${./decisions}
        MAESTRO_DISTRIBUTION_CACHE_SOURCE=${./distribution-cache.py}
        MAESTRO_QUALIFICATION_RESTORE_SOURCE=${./qualification-restore.py}
        export MAESTRO_DECISION_CORE MAESTRO_DISTRIBUTION_CACHE_SOURCE MAESTRO_QUALIFICATION_RESTORE_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3];
      source = ./qualification-restore.sh;
    };
    security-native-check = mkCommand {
      name = "security-native-check";
      prefix = ''
        MAESTRO_DECISION_CORE=${./decisions}
        MAESTRO_SECURITY_NATIVE_CHECK_SOURCE=${./security-native-check.py}
        export MAESTRO_DECISION_CORE MAESTRO_SECURITY_NATIVE_CHECK_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3];
      source = ./security-native-check.sh;
    };
    distribution-restore = mkCommand {
      name = "distribution-restore";
      prefix = ''
        MAESTRO_DECISION_CORE=${./decisions}
        export PYTHONPATH=${./decisions}
        MAESTRO_DISTRIBUTION_CACHE_SOURCE=${./distribution-cache.py}
        MAESTRO_DISTRIBUTION_RESTORE_SOURCE=${./distribution-restore.py}
        export MAESTRO_DECISION_CORE MAESTRO_DISTRIBUTION_CACHE_SOURCE MAESTRO_DISTRIBUTION_RESTORE_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
      source = ./distribution-restore.sh;
    };
    decision-refresh = mkCommand {
      name = "decision-refresh";
      prefix = ''
        MAESTRO_DECISION_CORE=${./decisions}
        export PYTHONPATH=${./decisions}
        MAESTRO_DISTRIBUTION_CACHE_SOURCE=${./distribution-cache.py}
        export MAESTRO_DISTRIBUTION_CACHE_SOURCE
        MAESTRO_DECISION_OPERATIONS_SOURCE=${./decision-refresh.py}
        export MAESTRO_DECISION_CORE MAESTRO_DECISION_OPERATIONS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras commands.security-scan];
      source = ./decision-refresh.sh;
    };
    decision-health = mkCommand {
      name = "decision-health";
      prefix = ''
        MAESTRO_DECISION_CORE=${./decisions}
        MAESTRO_DECISION_OPERATIONS_SOURCE=${./decision-health.py}
        export MAESTRO_DECISION_CORE MAESTRO_DECISION_OPERATIONS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
      source = ./decision-health.sh;
    };
    decision-handoff-fetch = mkCommand {
      name = "decision-handoff-fetch";
      prefix = ''
        export MAESTRO_OPERATIONS_SOURCE=${./decisions/operations.py}
        MAESTRO_DECISION_CORE=${./decisions}
        MAESTRO_DECISION_OPERATIONS_SOURCE=${./decision-handoff-fetch.py}
        export MAESTRO_DECISION_CORE MAESTRO_DECISION_OPERATIONS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
      source = ./decision-handoff-fetch.sh;
    };
    publication-inspect = mkCommand {
      name = "publication-inspect";
      prefix = ''
        export PUBLICATION_DESTINATIONS_SOURCE=${./decisions/destinations.py}
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.curl];
      source = ./publication-inspect.sh;
    };
    publication-journal = mkCommand {
      name = "publication-journal";
      prefix = ''
        MAESTRO_DECISIONS_SOURCE=${./decisions}
        MAESTRO_PUBLICATION_JOURNAL_SOURCE=${./publication-journal.py}
        MAESTRO_PUBLICATION_ASSETS_SOURCE=${./publication-assets.py}
        export MAESTRO_DECISIONS_SOURCE MAESTRO_PUBLICATION_JOURNAL_SOURCE MAESTRO_PUBLICATION_ASSETS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
      source = ./publication-journal.sh;
    };
    publication-assets = mkCommand {
      name = "publication-assets";
      prefix = ''
        MAESTRO_DECISIONS_SOURCE=${./decisions}
        MAESTRO_PUBLICATION_JOURNAL_SOURCE=${./publication-journal.py}
        MAESTRO_PUBLICATION_ASSETS_SOURCE=${./publication-assets.py}
        export MAESTRO_DECISIONS_SOURCE MAESTRO_PUBLICATION_JOURNAL_SOURCE MAESTRO_PUBLICATION_ASSETS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras commands.decision-handoff];
      source = ./publication-assets.sh;
    };
    consumer-probe = mkCommand {
      name = "consumer-probe";
      prefix = ''
        export PYTHONPATH=${./decisions}
        export MAESTRO_CONSUMER_PROBE_SOURCE=${./consumer-probe.py}
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3];
      source = ./consumer-probe.sh;
    };
    release-retain = mkCommand {
      name = "release-retain";
      runtimeInputs = commonInputs;
      source = ./release-retain.sh;
    };
    decision-download = mkCommand {
      name = "decision-download";
      prefix = ''
        export MAESTRO_OPERATIONS_SOURCE=${./decisions/operations.py}
        MAESTRO_DECISION_CORE=${./decisions}
        MAESTRO_DECISION_RETAINED_SOURCE=${./decision-retained.py}
        export MAESTRO_DECISION_CORE MAESTRO_DECISION_RETAINED_SOURCE
        MAESTRO_DECISION_DOWNLOAD_SOURCE=${./decision-download.py}
        export MAESTRO_DECISION_DOWNLOAD_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
      source = ./decision-download.sh;
    };
    decision-candidate = mkCommand {
      name = "decision-candidate";
      prefix = ''
        export PYTHONPATH=${./decisions}
        MAESTRO_DISTRIBUTION_CACHE_SOURCE=${./distribution-cache.py}
        export MAESTRO_DISTRIBUTION_CACHE_SOURCE
        MAESTRO_DECISION_CANDIDATE_SOURCE=${./decision-candidate.py}
        export MAESTRO_DECISION_CANDIDATE_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3];
      source = ./decision-candidate.sh;
    };
    source-security = mkCommand {
      name = "source-security";
      runtimeInputs = commonInputs ++ [pkgs.gitleaks];
      source = ./source-security.sh;
    };
    decision-event = mkCommand {
      name = "decision-event";
      runtimeInputs = commonInputs;
      source = ./decision-event.sh;
    };
    decision-admission = mkCommand {
      name = "decision-admission";
      prefix = ''
        MAESTRO_DECISIONS_SOURCE=${./decisions}
        export MAESTRO_DECISIONS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
      source = ./decision-admission.sh;
    };
    decision-publication = mkCommand {
      name = "decision-publication";
      prefix = ''
        MAESTRO_DECISIONS_SOURCE=${./decisions}
        export MAESTRO_DECISIONS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras commands.decision-handoff];
      source = ./decision-publication.sh;
    };
    decision-readiness = mkCommand {
      name = "decision-readiness";
      prefix = ''
        MAESTRO_DECISIONS_SOURCE=${./decisions}
        export MAESTRO_DECISIONS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
      source = ./decision-readiness.sh;
    };
    decision-reconcile = mkCommand {
      name = "decision-reconcile";
      prefix = ''
        MAESTRO_DECISIONS_SOURCE=${./decisions}
        export MAESTRO_DECISIONS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
      source = ./decision-reconcile.sh;
    };
    decision-check = mkCommand {
      name = "decision-check";
      prefix = ''
        MAESTRO_DECISIONS_SOURCE=${./decisions}
        export MAESTRO_DECISIONS_SOURCE
      '';
      runtimeInputs = [pkgs.python3 boundedGh pkgs.git pkgs.oras pkgs.coreutils];
      source = ./decision-check.sh;
    };
    decision-recovery = mkCommand {
      name = "decision-recovery";
      prefix = ''
        MAESTRO_DECISIONS_SOURCE=${./decisions}
        export MAESTRO_DECISIONS_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
      source = ./decision-recovery.sh;
    };
    decision-handoff = mkCommand {
      name = "decision-handoff";
      runtimeInputs = commonInputs ++ [commands.decision-handoff-fetch];
      source = ./decision-handoff.sh;
    };
    release-attestations = mkCommand {
      name = "release-attestations";
      runtimeInputs = commonInputs;
      source = ./release-attestations.sh;
    };
    release-request = mkCommand {
      name = "release-request";
      prefix = ''
        MAESTRO_RELEASE_REQUEST_SOURCE=${./release-request.py}
        export MAESTRO_RELEASE_REQUEST_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3];
      source = ./release-request.sh;
    };
    security-inventory-preflight = mkCommand {
      name = "security-inventory-preflight";
      prefix = ''
        MAESTRO_SECURITY_INVENTORY_SOURCE=${./security-inventory.py}
        export MAESTRO_SECURITY_INVENTORY_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3];
      source = ./security-inventory-preflight.sh;
    };
    security-inventory = mkCommand {
      name = "security-inventory";
      prefix = let
        context = pkgs.writeText "maestro-security-context.json" (builtins.toJSON {
          schemaVersion = 2;
          platform = pkgs.stdenv.hostPlatform.system;
          # Exact metadata identity, not an implicit build dependency. Native
          # task loading must not build the appliance before cache preflight;
          # the qualification plan materializes these outputs explicitly.
          system = builtins.unsafeDiscardStringContext appliance.system.build.toplevel.outPath;
          distributionRoots = map builtins.unsafeDiscardStringContext distributionRoots;
          installerQualification = builtins.fromJSON (builtins.unsafeDiscardStringContext (builtins.toJSON installerQualification));
          lockDigest = builtins.hashFile "sha256" lockFile;
          inherit packageSourceRoots;
          inventoryDigest = builtins.hashFile "sha256" ./security-inventory.py;
          normalizerDigest = builtins.hashFile "sha256" ./security-normalize.py;
          runtime = {
            inherit (appliance.networking.firewall) allowedTCPPorts allowedUDPPorts;
            managementCIDRs = appliance.maestro.operator.managementCIDRs;
            ssh = appliance.services.openssh.settings;
            xoPackage = builtins.unsafeDiscardStringContext appliance.maestro.xo.package.outPath;
            xoChannel = appliance.maestro.xo.channel;
            xoUser = appliance.maestro.xo.user;
            fileRestore = {
              inherit (appliance.maestro.xo.fileRestore) enable;
              helper = builtins.unsafeDiscardStringContext appliance.systemd.services.xo-server.environment.XO_FILE_RESTORE_HELPER;
            };
            storage = {
              inherit (appliance.maestro.xo.storage) enableNFS enableCIFS enableVHD mountsDir;
            };
            inherit (appliance.systemd.services.xo-server.serviceConfig) CapabilityBoundingSet AmbientCapabilities User Group;
            sudo = appliance.security.sudo.extraRules;
            valkey = appliance.services.redis.servers.xo.settings;
          };
        });
      in ''
        MAESTRO_SECURITY_INVENTORY_SOURCE=${./security-inventory.py}
        MAESTRO_SECURITY_CONTEXT=${context}
        export MAESTRO_SECURITY_INVENTORY_SOURCE MAESTRO_SECURITY_CONTEXT
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3];
      source = ./security-inventory.sh;
    };
    packer-validate = mkCommand {
      name = "packer-validate";
      runtimeInputs = commonInputs ++ [packerXenserver pkgs.openssh];
      source = ./packer-validate.sh;
    };
    security-verdict = mkCommand {
      name = "security-verdict";
      prefix = ''
        MAESTRO_SECURITY_VERDICT_SOURCE=${./security-verdict.py}
        export MAESTRO_SECURITY_VERDICT_SOURCE
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3];
      source = ./security-verdict.sh;
    };
    security-applicability = mkCommand {
      name = "security-applicability";
      prefix = ''
        MAESTRO_SECURITY_APPLICABILITY_RULES=${./security-applicability.json}
        export MAESTRO_SECURITY_APPLICABILITY_RULES
      '';
      runtimeInputs = commonInputs ++ [applicabilityCommand];
      source = ./security-applicability.sh;
    };
    security-scan = mkCommand {
      name = "security-scan";
      prefix = ''
        MAESTRO_SECURITY_POLICY="''${MAESTRO_SYSTEM_ROOT:-$PWD}/nix/automation/security-policy.json"
        export MAESTRO_SECURITY_POLICY
        MAESTRO_SECURITY_NORMALIZE_SOURCE=${./security-normalize.py}
        export MAESTRO_SECURITY_NORMALIZE_SOURCE
      '';
      runtimeInputs =
        commonInputs
        ++ [
          pkgs.grype
          pkgs.cargo-audit
          commands.security-verdict
          commands.security-applicability
          (pkgs.python3.withPackages (pythonPackages: [pythonPackages.cvss]))
        ];
      source = ./security-scan.sh;
    };
    security-latest = mkCommand {
      name = "security-latest";
      runtimeInputs = commonInputs ++ [commands.download-installer commands.security-scan];
      source = ./security-latest.sh;
    };
    policy-drift = mkCommand {
      name = "policy-drift";
      prefix = ''
        MAESTRO_GITHUB_SECURITY_POLICY=${./github/security-policy.json}
        MAESTRO_MAIN_RULESET=${./github/main-ruleset.json}
        export MAESTRO_GITHUB_SECURITY_POLICY MAESTRO_MAIN_RULESET
      '';
      runtimeInputs = commonInputs;
      source = ./policy-drift.sh;
    };
    download-installer = mkCommand {
      name = "download-installer";
      runtimeInputs = commonInputs ++ [commands.verify-state commands.verify-inventory];
      source = ./download-installer.sh;
    };
    sign-check = mkCommand {
      name = "sign-check";
      runtimeInputs = commonInputs ++ [commands.validate-state];
      source = ./sign-check.sh;
    };
    validate-state = mkCommand {
      name = "validate-state";
      prefix = ''
        MAESTRO_QUALIFICATION_STATE_SCHEMA=${./qualification-state.schema.json}
        export MAESTRO_QUALIFICATION_STATE_SCHEMA
      '';
      runtimeInputs = commonInputs ++ [pkgs.check-jsonschema];
      source = ./validate-state.sh;
    };
    trusted-run = mkCommand {
      name = "trusted-run";
      runtimeInputs = commonInputs;
      source = ./trusted-run.sh;
    };
    verify-state = mkCommand {
      name = "verify-state";
      runtimeInputs = commonInputs ++ [commands.validate-state commands.trusted-run];
      source = ./verify-state.sh;
    };
    verify-inventory = mkCommand {
      name = "verify-inventory";
      runtimeInputs = commonInputs ++ [commands.validate-state commands.trusted-run];
      source = ./verify-inventory.sh;
    };
    boot-media = mkCommand {
      name = "boot-media";
      runtimeInputs = commonInputs ++ [pkgs.qemu_kvm];
      source = ./boot-media.sh;
    };
    qualification-cache = mkCommand {
      name = "qualification-cache";
      runtimeInputs = commonInputs;
      source = ./qualification-cache.sh;
    };
    qualification-assets = mkCommand {
      name = "qualification-assets";
      prefix = ''
        MAESTRO_SPDX_SCHEMA="''${MAESTRO_SPDX_SCHEMA:-${spdxSchema}}"
        export MAESTRO_SPDX_SCHEMA
      '';
      runtimeInputs = commonInputs ++ [pkgs.check-jsonschema planRunner commands.validate-state commands.verify-inventory commands.verify-state commands.security-inventory commands.security-inventory-preflight commands.qualification-cache];
      source = ./qualification-assets.sh;
    };
    qualification-inputs = mkCommand {
      name = "qualification-inputs";
      runtimeInputs = commonInputs;
      source = ./qualification-inputs.sh;
    };
    cache-validation = mkCommand {
      name = "cache-validation";
      prefix = ''
        MAESTRO_CI_PLAN_CONTRACT=${../ci-plans.json}
        export MAESTRO_CI_PLAN_CONTRACT
      '';
      runtimeInputs = commonInputs ++ [pkgs.cachix commands.decision-publication commands.decision-handoff];
      source = ./cache-validation.sh;
    };
    repository-audit = mkCommand {
      name = "repository-audit";
      runtimeInputs = commonInputs ++ [planRunner commands.security-inventory-preflight];
      source = ./repository-audit.sh;
    };
    classify = mkCommand {
      name = "classify";
      runtimeInputs = commonInputs ++ [classifyPaths];
      source = ./classify.sh;
    };
    classify-paths = classifyPaths;
    fix-hashes = mkCommand {
      name = "fix-hashes";
      runtimeInputs = commonInputs;
      source = ./fix-hashes.sh;
    };
    verdict = mkCommand {
      name = "verdict";
      runtimeInputs = with pkgs; [
        bash
        coreutils
        jq
      ];
      source = ./verdict.sh;
    };
    lock-validate = mkCommand {
      name = "lock-validate";
      runtimeInputs = commonInputs;
      source = ./lock-validate.sh;
    };
    open-update-pr = mkCommand {
      name = "open-update-pr";
      runtimeInputs = commonInputs;
      source = ./open-update-pr.sh;
    };
    route = mkCommand {
      name = "route";
      runtimeInputs =
        commonInputs
        ++ [
          commands.classify
          commands.resolve-qualification
          validatePlan
        ];
      source = ./route-plan.sh;
    };
    publish = mkCommand {
      name = "publish";
      prefix = ''
        export PUBLICATION_DESTINATIONS_SOURCE=${./decisions/destinations.py}
      '';
      runtimeInputs = commonInputs ++ [pkgs.cachix pkgs.python3 pkgs.curl commands.decision-publication commands.distribution-restore commands.decision-handoff];
      source = ./publish.sh;
    };
    queue = mkCommand {
      name = "queue";
      runtimeInputs = commonInputs ++ [commands.trusted-update];
      source = ./queue.sh;
    };
    release-manager = mkCommand {
      name = "release-manager";
      runtimeInputs =
        commonInputs
        ++ [
          pkgs.gzip
          commands.qualification-inputs
          commands.release-notes
          commands.release-stage
          commands.release-version
          commands.publication-assets
          commands.trusted-update
          commands.validate-state
          commands.verify-inventory
          commands.trusted-run
        ];
      source = ./release-manager.sh;
    };
    release-notes = mkCommand {
      name = "release-notes";
      runtimeInputs = commonInputs;
      source = ./release-notes.sh;
    };
    release-stage = mkCommand {
      name = "release-stage";
      runtimeInputs = commonInputs;
      source = ./release-split.sh;
    };
    release-version = mkCommand {
      name = "release-version";
      runtimeInputs = commonInputs;
      source = ./release-version.sh;
    };
    resolve-qualification = mkCommand {
      name = "resolve-qualification";
      prefix = ''
        export MAESTRO_OPERATIONS_SOURCE=${./decisions/operations.py}
      '';
      runtimeInputs = commonInputs ++ [pkgs.python3 commands.qualification-inputs commands.validate-state commands.trusted-run commands.verify-state commands.verify-inventory];
      source = ./qualification-resolve.sh;
    };
    trusted-update = mkCommand {
      name = "trusted-update";
      runtimeInputs = commonInputs;
      source = ./trusted-update.sh;
    };
    update-locks = mkCommand {
      name = "update-locks";
      runtimeInputs = commonInputs;
      source = ./update-locks.sh;
    };
    validate-plan = validatePlan;
  };
in
  commands
