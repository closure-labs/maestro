{...}: {
  perSystem = {pkgs, ...}: {
    packages.maestro-ci-graph-result = pkgs.writeShellApplication {
      name = "maestro-ci-graph-result";
      runtimeInputs = [pkgs.python3];
      text = ''
        export PYTHONDONTWRITEBYTECODE=1
        export PYTHONPATH=${./_source}
        exec python3 ${./_source/result.py}
      '';
    };
  };
}
