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
  packer-validate = mkCommand {
    name = "packer-validate";
    runtimeInputs = commonInputs ++ [packerXenserver pkgs.openssh];
    source = ../_source/packer-validate.sh;
  };
}
