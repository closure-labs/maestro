{...}: let
  inherit (import ../../../features/development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "ci:transport:verify-inventory".exec = runFlakePackage "maestro-ci-job-transfer" "verify inventory inventory-transfer";
    "ci:graph:summary".exec = runFlakePackage "maestro-ci-graph-summary" "";
    "ci:graph:write-plans".exec = runFlakePackage "maestro-ci-graph-write-plans" "";
    "ci:graph:equivalence".exec = runFlakePackage "maestro-ci-graph-equivalence" "";
    "ci:graph:result".exec = runFlakePackage "maestro-ci-graph-result" "";
    "ci:transport:restore-appliance".exec = runFlakePackage "maestro-ci-job-transfer" "restore appliance appliance-transfer";
    "ci:transport:restore-installer".exec = runFlakePackage "maestro-ci-job-transfer" "restore installer installer-transfer";
    "ci:transport:export-inventory".exec = runFlakePackage "maestro-ci-job-transfer" "export inventory inventory-transfer";
    "ci:transport:restore-inventory".exec = runFlakePackage "maestro-ci-job-transfer" "restore inventory inventory-transfer";

    "ci:graph:plan".exec = runFlakePackage "maestro-ci-graph-plan" "";
    "ci:route".exec = runFlakePackage "maestro-ci-route" "";
    "ci:classify".exec = runFlakePackage "maestro-ci-classify" "";
  };
}
