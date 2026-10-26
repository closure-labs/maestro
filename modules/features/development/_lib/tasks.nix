{...}: let
  inherit (import ./task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "flake:write".exec = runFlakePackage "write-flake" "";
    "ci:codeql:rust-toolchain".exec = runFlakePackage "maestro-ci-codeql-rust-toolchain" "";
    "automation:fix-hashes".exec = runFlakePackage "maestro-ci-fix-hashes" "";
    "automation:update-locks".exec = runFlakePackage "maestro-ci-update-locks" "";
    "automation:validate-locks".exec = runFlakePackage "maestro-ci-lock-validate" "";
    "automation:open-lock-update-pr".exec =
      runFlakePackage "maestro-ci-open-update-pr" "flake.lock devenv.lock";
  };
}
