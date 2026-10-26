{...}: let
  inherit (import ../../../features/development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "release:retain".exec = runFlakePackage "maestro-ci-release-retain" "";
    "release:inspect".exec = runFlakePackage "maestro-ci-publication-inspect" "";
    "release:journal".exec = runFlakePackage "maestro-ci-publication-journal" "";
    "release:diagnostics".exec = runFlakePackage "maestro-ci-publication-diagnostics" "";
    "release:reserve".exec = runFlakePackage "maestro-ci-release-reservation" "";
    "release:complete".exec = runFlakePackage "maestro-ci-release-completion" "";
    "release:assets".exec = runFlakePackage "maestro-ci-publication-assets" "";
    "ci:publish".exec = runFlakePackage "maestro-ci-publish" "";
    "release:request".exec = runFlakePackage "maestro-ci-release-request" "create";
    "release:signal".exec = runFlakePackage "maestro-ci-release-request" "signal";
    "release:pending".exec = runFlakePackage "maestro-ci-release-request" "pending";
    "release:continuation".exec = runFlakePackage "maestro-ci-release-request" "resolve";
    "release:prepare".exec = runFlakePackage "maestro-ci-release-manager" "prepare";
    "release:dispatch".exec = runFlakePackage "maestro-ci-release-manager" "dispatch";
    "release:inventory".exec = runFlakePackage "maestro-ci-release-manager" "inventory";
    "release:verify".exec = runFlakePackage "maestro-ci-release-manager" "verify";
    "release:attestations".exec = runFlakePackage "maestro-ci-release-attestations" "";
    "release:stage".exec = runFlakePackage "maestro-ci-release-manager" "stage";
    "release:draft".exec = runFlakePackage "maestro-ci-release-manager" "draft";
    "release:publish".exec = runFlakePackage "maestro-ci-release-manager" "publish";
    "release:advance".exec = runFlakePackage "maestro-ci-release-manager" "advance";
  };
}
