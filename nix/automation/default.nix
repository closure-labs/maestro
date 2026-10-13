{
  planRunner,
  packerXenserver,
  pkgs,
  appliance,
  lockFile,
  packageSourceRoots,
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

  commonInputs = with pkgs; [
    bash
    coreutils
    findutils
    git
    gh
    gnugrep
    gnused
    jq
    nix
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
          lockDigest = builtins.hashFile "sha256" lockFile;
          inherit packageSourceRoots;
          inventoryDigest = builtins.hashFile "sha256" ./security-inventory.py;
          normalizerDigest = builtins.hashFile "sha256" ./security-normalize.py;
          runtime = {
            inherit (appliance.networking.firewall) allowedTCPPorts allowedUDPPorts;
            ssh = appliance.services.openssh.settings;
            xoPackage = builtins.unsafeDiscardStringContext appliance.maestro.xo.package.outPath;
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
    qualification-assets = mkCommand {
      name = "qualification-assets";
      prefix = ''
        MAESTRO_SPDX_SCHEMA="''${MAESTRO_SPDX_SCHEMA:-${spdxSchema}}"
        export MAESTRO_SPDX_SCHEMA
      '';
      runtimeInputs = commonInputs ++ [pkgs.check-jsonschema planRunner commands.validate-state commands.verify-inventory commands.verify-state commands.security-inventory];
      source = ./qualification-assets.sh;
    };
    qualification-inputs = mkCommand {
      name = "qualification-inputs";
      runtimeInputs = commonInputs;
      source = ./qualification-inputs.sh;
    };
    repository-audit = mkCommand {
      name = "repository-audit";
      runtimeInputs = commonInputs ++ [planRunner];
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
      runtimeInputs = commonInputs ++ [pkgs.cachix planRunner];
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
      runtimeInputs = commonInputs ++ [commands.qualification-inputs commands.validate-state commands.trusted-run commands.verify-state commands.verify-inventory];
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
