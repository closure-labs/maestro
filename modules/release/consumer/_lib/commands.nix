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
  consumer-probe = mkCommand {
    name = "consumer-probe";
    prefix = ''
      export PYTHONPATH=${../../../ci/authority/_source/decisions}
      export MAESTRO_CONSUMER_PROBE_SOURCE=${../_source/consumer-probe.py}
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3];
    source = ../_source/consumer-probe.sh;
  };
}
