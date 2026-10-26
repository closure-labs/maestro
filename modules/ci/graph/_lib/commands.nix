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
  classify = mkCommand {
    name = "classify";
    runtimeInputs = commonInputs ++ [classifyPaths];
    source = ../_source/classify.sh;
  };
  classify-paths = classifyPaths;
  route = mkCommand {
    name = "route";
    runtimeInputs =
      commonInputs
      ++ [
        commands.classify
        commands.resolve-qualification
        validatePlan
        commands.decision-only
      ];
    source = ../_source/route-plan.sh;
  };
  validate-plan = validatePlan;
}
