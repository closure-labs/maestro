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
  cache-validation = mkCommand {
    name = "cache-validation";
    prefix = ''
      MAESTRO_CI_PLAN_CONTRACT=${../../graph/_lib/plans.json}
      export MAESTRO_CI_PLAN_CONTRACT
    '';
    runtimeInputs = commonInputs ++ [pkgs.cachix commands.decision-publication commands.decision-handoff];
    source = ../_source/cache-validation.sh;
  };
  repository-audit = mkCommand {
    name = "repository-audit";
    runtimeInputs = commonInputs ++ [planRunner commands.security-inventory-preflight];
    source = ../_source/repository-audit.sh;
  };
  verdict = mkCommand {
    name = "verdict";
    runtimeInputs = with pkgs; [
      bash
      coreutils
      jq
    ];
    source = ../_source/verdict.sh;
  };
}
