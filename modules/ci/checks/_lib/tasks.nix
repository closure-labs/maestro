{...}: let
  inherit (import ../../../features/development/_lib/task-helpers.nix {}) withFlake runFlakePackage;
in {
  tasks = {
    "ci:source-security".exec = runFlakePackage "maestro-ci-source-security" "";
    "ci:repository-audit:format" = {
      exec = withFlake ''
        cd "$DEVENV_ROOT"
        if git rev-parse --show-toplevel >/dev/null 2>&1; then
          mapfile -d $'\0' -t nix_files < <(git ls-files -z -- '*.nix')
        else
          # jj workspaces do not expose .git. Ignore generated environment
          # state while retaining a useful local formatting check.
          mapfile -d $'\0' -t nix_files < <(
            find . \( -path './.devenv' -o -path './.direnv' \) -prune \
              -o -type f -name '*.nix' -print0
          )
        fi
        system="$(nix eval --impure --raw --expr builtins.currentSystem)"
        nix run --accept-flake-config "$flake_ref#formatter.$system" -- \
          --check "''${nix_files[@]}"
      '';
      execIfModified = [
        "*.nix"
        "**/*.nix"
      ];
    };
    "ci:repository-audit:flake" = {
      exec = ''
        export MAESTRO_CI_AUDIT_MANIFEST="''${MAESTRO_CI_AUDIT_MANIFEST:-$DEVENV_STATE/maestro-validation.json}"
        ${runFlakePackage "maestro-ci-repository-audit" "--no-write-lock-file"}
      '';
      # Reuse is safe only for an identical checkout; every tracked source or
      # documentation change is allowed to invalidate the complete contract.
      execIfModified = ["."];
    };
    "ci:repository-audit" = {
      after = [
        "ci:repository-audit:flake"
        "ci:repository-audit:format"
      ];
    };

    "ci:cache-validation" = {
      after = ["ci:repository-audit"];
      exec = runFlakePackage "maestro-ci-cache-validation" ''
        "''${MAESTRO_CI_AUDIT_MANIFEST:-$DEVENV_STATE/maestro-validation.json}"
      '';
    };

    "ci:verdict".exec = runFlakePackage "maestro-ci-verdict" "";
  };
}
