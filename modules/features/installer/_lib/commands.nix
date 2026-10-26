{
  pkgs,
  planRunner,
  packerXenserver,
  ciNix,
  appliance,
  lockFile,
  packageSourceRoots,
  applicabilityCommand,
  distributionRoots,
  installerQualification,
  devenv,
  commands,
  common,
}: let
  inherit (common) mkCommand commonInputs spdxSchema boundedGh publicCacheWorker validatePlan classifyPaths;
in {
  qualification-restore = mkCommand {
    name = "qualification-restore";
    prefix = ''
      MAESTRO_DECISION_CORE=${../../../ci/authority/_source/decisions}
      export PYTHONPATH=${../../../ci/authority/_source/decisions}
      MAESTRO_DISTRIBUTION_CACHE_SOURCE=${../../../ci/authority/_source/distribution-cache.py}
      MAESTRO_QUALIFICATION_RESTORE_SOURCE=${../../../ci/authority/_source/qualification-restore.py}
      export MAESTRO_DECISION_CORE MAESTRO_DISTRIBUTION_CACHE_SOURCE MAESTRO_QUALIFICATION_RESTORE_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3];
    source = ../../../ci/authority/_source/qualification-restore.sh;
  };
  download-installer = mkCommand {
    name = "download-installer";
    runtimeInputs = commonInputs ++ [commands.verify-state commands.verify-inventory];
    source = ../../../ci/authority/_source/download-installer.sh;
  };
  sign-check = mkCommand {
    name = "sign-check";
    runtimeInputs = commonInputs ++ [commands.validate-state];
    source = ../../../ci/authority/_source/sign-check.sh;
  };
  validate-state = mkCommand {
    name = "validate-state";
    prefix = ''
      MAESTRO_QUALIFICATION_STATE_SCHEMA=${../../../ci/authority/_source/qualification-state.schema.json}
      export MAESTRO_QUALIFICATION_STATE_SCHEMA
    '';
    runtimeInputs = commonInputs ++ [pkgs.check-jsonschema];
    source = ../../../ci/authority/_source/validate-state.sh;
  };
  verify-state = mkCommand {
    name = "verify-state";
    runtimeInputs = commonInputs ++ [commands.validate-state commands.trusted-run];
    source = ../../../ci/authority/_source/verify-state.sh;
  };
  verify-inventory = mkCommand {
    name = "verify-inventory";
    runtimeInputs = commonInputs ++ [commands.validate-state commands.trusted-run];
    source = ../../../ci/authority/_source/verify-inventory.sh;
  };
  boot-media = mkCommand {
    name = "boot-media";
    runtimeInputs = commonInputs ++ [pkgs.qemu_kvm];
    source = ../../../ci/authority/_source/boot-media.sh;
  };
  qualification-cache = mkCommand {
    name = "qualification-cache";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/qualification-cache.sh;
  };
  qualification-assets = mkCommand {
    name = "qualification-assets";
    prefix = ''
      MAESTRO_SPDX_SCHEMA="''${MAESTRO_SPDX_SCHEMA:-${spdxSchema}}"
      export MAESTRO_SPDX_SCHEMA
    '';
    runtimeInputs = commonInputs ++ [pkgs.check-jsonschema planRunner commands.validate-state commands.verify-inventory commands.verify-state commands.security-inventory commands.security-inventory-preflight commands.qualification-cache];
    source = ../../../ci/authority/_source/qualification-assets.sh;
  };
  qualification-inputs = mkCommand {
    name = "qualification-inputs";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/qualification-inputs.sh;
  };
  resolve-qualification = mkCommand {
    name = "resolve-qualification";
    prefix = ''
      export MAESTRO_OPERATIONS_SOURCE=${../../../ci/authority/_source/decisions/operations.py}
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 commands.qualification-inputs commands.validate-state commands.trusted-run commands.verify-state commands.verify-inventory];
    source = ../../../ci/authority/_source/qualification-resolve.sh;
  };
}
