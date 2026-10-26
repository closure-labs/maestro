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
  trusted-ci-admission = pkgs.writeShellApplication {
    name = "maestro-ci-trusted-ci-admission";
    runtimeInputs = [pkgs.python3 boundedGh];
    text = ''
      export PYTHONPATH=${../_source/decisions}
      exec python3 ${../_source/decisions/ci_admission.py} --policy ${../_source/ci-admission-policy.json}
    '';
  };
  decision-only = mkCommand {
    name = "decision-only";
    prefix = ''
      export MAESTRO_DECISIONS_SOURCE=${../_source/decisions}
      export MAESTRO_DECISION_RETAINED_SOURCE=${../_source/decision-retained.py}
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras commands.verify-state];
    source = ../_source/decision-only.sh;
  };
  distribution-restore = mkCommand {
    name = "distribution-restore";
    prefix = ''
      MAESTRO_DECISION_CORE=${../_source/decisions}
      export PYTHONPATH=${../_source/decisions}
      MAESTRO_DISTRIBUTION_CACHE_SOURCE=${../_source/distribution-cache.py}
      MAESTRO_DISTRIBUTION_RESTORE_SOURCE=${../_source/distribution-restore.py}
      export MAESTRO_DECISION_CORE MAESTRO_DISTRIBUTION_CACHE_SOURCE MAESTRO_DISTRIBUTION_RESTORE_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
    source = ../_source/distribution-restore.sh;
  };
  decision-refresh = mkCommand {
    name = "decision-refresh";
    prefix = ''
      MAESTRO_DECISION_CORE=${../_source/decisions}
      export PYTHONPATH=${../_source/decisions}
      MAESTRO_DISTRIBUTION_CACHE_SOURCE=${../_source/distribution-cache.py}
      export MAESTRO_DISTRIBUTION_CACHE_SOURCE
      MAESTRO_DECISION_OPERATIONS_SOURCE=${../_source/decision-refresh.py}
      export MAESTRO_DECISION_CORE MAESTRO_DECISION_OPERATIONS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras commands.security-scan];
    source = ../_source/decision-refresh.sh;
  };
  decision-health = mkCommand {
    name = "decision-health";
    prefix = ''
      MAESTRO_DECISION_CORE=${../_source/decisions}
      MAESTRO_DECISION_OPERATIONS_SOURCE=${../_source/decision-health.py}
      export MAESTRO_DECISION_CORE MAESTRO_DECISION_OPERATIONS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
    source = ../_source/decision-health.sh;
  };
  decision-handoff-fetch = mkCommand {
    name = "decision-handoff-fetch";
    prefix = ''
      export MAESTRO_OPERATIONS_SOURCE=${../_source/decisions/operations.py}
      MAESTRO_DECISION_CORE=${../_source/decisions}
      MAESTRO_DECISION_OPERATIONS_SOURCE=${../_source/decision-handoff-fetch.py}
      export MAESTRO_DECISION_CORE MAESTRO_DECISION_OPERATIONS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.curl pkgs.python3 pkgs.oras];
    source = ../_source/decision-handoff-fetch.sh;
  };
  decision-download = mkCommand {
    name = "decision-download";
    prefix = ''
      export MAESTRO_OPERATIONS_SOURCE=${../_source/decisions/operations.py}
      MAESTRO_DECISION_CORE=${../_source/decisions}
      MAESTRO_DECISION_RETAINED_SOURCE=${../_source/decision-retained.py}
      export MAESTRO_DECISION_CORE MAESTRO_DECISION_RETAINED_SOURCE
      MAESTRO_DECISION_DOWNLOAD_SOURCE=${../_source/decision-download.py}
      export MAESTRO_DECISION_DOWNLOAD_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
    source = ../_source/decision-download.sh;
  };
  decision-candidate = mkCommand {
    name = "decision-candidate";
    prefix = ''
      export PYTHONPATH=${../_source/decisions}
      MAESTRO_DISTRIBUTION_CACHE_SOURCE=${../_source/distribution-cache.py}
      export MAESTRO_DISTRIBUTION_CACHE_SOURCE
      MAESTRO_DECISION_CANDIDATE_SOURCE=${../_source/decision-candidate.py}
      export MAESTRO_DECISION_CANDIDATE_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3];
    source = ../_source/decision-candidate.sh;
  };
  decision-event = mkCommand {
    name = "decision-event";
    runtimeInputs = commonInputs;
    source = ../_source/decision-event.sh;
  };
  decision-admission = mkCommand {
    name = "decision-admission";
    prefix = ''
      MAESTRO_DECISIONS_SOURCE=${../_source/decisions}
      export MAESTRO_DECISIONS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
    source = ../_source/decision-admission.sh;
  };
  decision-publication = mkCommand {
    name = "decision-publication";
    prefix = ''
      MAESTRO_DECISIONS_SOURCE=${../_source/decisions}
      export MAESTRO_DECISIONS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras commands.decision-handoff];
    source = ../_source/decision-publication.sh;
  };
  decision-readiness = mkCommand {
    name = "decision-readiness";
    prefix = ''
      MAESTRO_DECISIONS_SOURCE=${../_source/decisions}
      export MAESTRO_DECISIONS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
    source = ../_source/decision-readiness.sh;
  };
  decision-reconcile = mkCommand {
    name = "decision-reconcile";
    prefix = ''
      MAESTRO_DECISIONS_SOURCE=${../_source/decisions}
      export MAESTRO_DECISIONS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
    source = ../_source/decision-reconcile.sh;
  };
  decision-check = mkCommand {
    name = "decision-check";
    prefix = ''
      MAESTRO_DECISIONS_SOURCE=${../_source/decisions}
      export MAESTRO_DECISIONS_SOURCE
    '';
    runtimeInputs = [pkgs.python3 boundedGh pkgs.git pkgs.oras pkgs.coreutils];
    source = ../_source/decision-check.sh;
  };
  decision-recovery = mkCommand {
    name = "decision-recovery";
    prefix = ''
      MAESTRO_DECISIONS_SOURCE=${../_source/decisions}
      export MAESTRO_DECISIONS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
    source = ../_source/decision-recovery.sh;
  };
  decision-handoff = mkCommand {
    name = "decision-handoff";
    runtimeInputs = commonInputs ++ [commands.decision-handoff-fetch];
    source = ../_source/decision-handoff.sh;
  };
  trusted-run = mkCommand {
    name = "trusted-run";
    runtimeInputs = commonInputs;
    source = ../_source/trusted-run.sh;
  };
  queue = mkCommand {
    name = "queue";
    runtimeInputs = commonInputs ++ [commands.trusted-update];
    source = ../_source/queue.sh;
  };
}
