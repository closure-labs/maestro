{...}: let
  inherit (import ../../../features/development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "ci:security:verify-native".exec = runFlakePackage "maestro-ci-security-native-check" "";
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
  };
}
