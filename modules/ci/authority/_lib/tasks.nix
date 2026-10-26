{...}: let
  inherit (import ../../../features/development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "cache:doctor".exec = runFlakePackage "maestro-ci-cache-doctor" "";
    "ci:distribution:restore".exec = runFlakePackage "maestro-ci-distribution-restore" "";
    "ci:decision:refresh".exec = runFlakePackage "maestro-ci-decision-refresh" "";
    "ci:decision:health".exec = runFlakePackage "maestro-ci-decision-health" "";
    "ci:consumer-probe".exec = runFlakePackage "maestro-ci-consumer-probe" "";
    "ci:decision:download".exec = runFlakePackage "maestro-ci-decision-download" "";
    "ci:decision:candidate".exec = runFlakePackage "maestro-ci-decision-candidate" "";
    "ci:decision:admission".exec = runFlakePackage "maestro-ci-decision-admission" "";
    "ci:decision:publication".exec = runFlakePackage "maestro-ci-decision-publication" "";
    "ci:decision:readiness".exec = runFlakePackage "maestro-ci-decision-readiness" "";
    "ci:decision:reconcile".exec = runFlakePackage "maestro-ci-decision-reconcile" "";
    "ci:decision:check".exec = runFlakePackage "maestro-ci-decision-check" "";
    "ci:decision:recovery".exec = runFlakePackage "maestro-ci-decision-recovery" "";
    "ci:decision:handoff".exec = runFlakePackage "maestro-ci-decision-handoff" "";
    "ci:decision:event".exec = runFlakePackage "maestro-ci-decision-event" "";
    "ci:retained-evidence".exec = runFlakePackage "maestro-ci-decision-only" "";
    "ci:admit-trusted".exec = runFlakePackage "maestro-ci-trusted-ci-admission" "";
    "automation:queue".exec = runFlakePackage "maestro-ci-queue" "";
  };
}
