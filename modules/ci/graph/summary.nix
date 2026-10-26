{...}: {
  perSystem = {pkgs, ...}: {
    packages.maestro-ci-graph-summary = pkgs.writeShellApplication {
      name = "maestro-ci-graph-summary";
      runtimeInputs = [pkgs.python3 pkgs.gh];
      text = ''
        export PYTHONDONTWRITEBYTECODE=1
        exec python3 ${./_source/summary.py}
      '';
    };
  };
}
