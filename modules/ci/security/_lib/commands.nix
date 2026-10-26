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
  security-native-check = mkCommand {
    name = "security-native-check";
    prefix = ''
      MAESTRO_DECISION_CORE=${../../authority/_source/decisions}
      MAESTRO_SECURITY_NATIVE_CHECK_SOURCE=${../_source/security-native-check.py}
      export MAESTRO_DECISION_CORE MAESTRO_SECURITY_NATIVE_CHECK_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3];
    source = ../_source/security-native-check.sh;
  };
  source-security = mkCommand {
    name = "source-security";
    prefix = ''
      export MAESTRO_SOURCE_SECURITY_SOURCE=${../_source/source-security.py}
    '';
    runtimeInputs = commonInputs ++ [pkgs.gitleaks pkgs.python3];
    source = ../_source/source-security.sh;
  };
  security-verdict = mkCommand {
    name = "security-verdict";
    prefix = ''
      MAESTRO_SECURITY_VERDICT_SOURCE=${../_source/security-verdict.py}
      export MAESTRO_SECURITY_VERDICT_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3];
    source = ../_source/security-verdict.sh;
  };
  security-scan = mkCommand {
    name = "security-scan";
    prefix = ''
      MAESTRO_SECURITY_POLICY="''${MAESTRO_SYSTEM_ROOT:-$PWD}/modules/ci/security/_source/security-policy.json"
      export MAESTRO_SECURITY_POLICY
      export MAESTRO_FINGERPRINTS_CORE=${../../authority/_source/decisions}
      MAESTRO_SECURITY_NORMALIZE_SOURCE=${../_source/security-normalize.py}
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
    source = ../_source/security-scan.sh;
  };
  security-latest = mkCommand {
    name = "security-latest";
    runtimeInputs = commonInputs ++ [commands.download-installer commands.security-scan];
    source = ../_source/security-latest.sh;
  };
  policy-drift = mkCommand {
    name = "policy-drift";
    prefix = ''
      MAESTRO_GITHUB_SECURITY_POLICY=${../../authority/_source/github/security-policy.json}
      MAESTRO_MAIN_RULESET=${../../authority/_source/github/main-ruleset.json}
      export MAESTRO_GITHUB_SECURITY_POLICY MAESTRO_MAIN_RULESET
    '';
    runtimeInputs = commonInputs;
    source = ../_source/policy-drift.sh;
  };
}
