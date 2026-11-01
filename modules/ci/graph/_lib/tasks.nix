{...}: let
  inherit (import ../../../features/development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "ci:graph:reference".exec = runFlakePackage "maestro-ci-graph-reference" "";
    "ci:graph:compare".exec = runFlakePackage "maestro-ci-graph-compare" "";
    "ci:inventory:bind".exec = runFlakePackage "maestro-ci-job-transfer" "bind inventory inventory-binding";
    "ci:inventory:verify".exec = runFlakePackage "maestro-ci-job-transfer" "verify inventory inventory-binding";
    "ci:graph:summary".exec = runFlakePackage "maestro-ci-graph-summary" "";
    "ci:graph:write-plans".exec = runFlakePackage "maestro-ci-graph-write-plans" "";
    "ci:graph:equivalence".exec = runFlakePackage "maestro-ci-graph-equivalence" "";
    "ci:graph:result".exec = runFlakePackage "maestro-ci-graph-result" "";
    "ci:transport:restore-appliance".exec = runFlakePackage "maestro-ci-job-transfer" "restore appliance appliance-transfer";
    "ci:transport:restore-installer".exec = runFlakePackage "maestro-ci-job-transfer" "restore installer installer-transfer";

    "ci:graph:plan".exec = runFlakePackage "maestro-ci-graph-plan" "";
    "ci:route".exec = runFlakePackage "maestro-ci-route" "";
    "ci:classify".exec = runFlakePackage "maestro-ci-classify" "";
  };
}
