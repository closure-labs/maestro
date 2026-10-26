{...}: {
  perSystem = {
    pkgs,
    ciNix,
    ...
  }: {
    packages.maestro-ci-job-transfer = pkgs.writeShellApplication {
      name = "maestro-ci-job-transfer";
      runtimeInputs = [pkgs.python3 ciNix];
      text = ''
        export PYTHONDONTWRITEBYTECODE=1
        export MAESTRO_DECISION_CORE=${../authority/_source/decisions}
        export MAESTRO_DISTRIBUTION_CACHE_SOURCE=${../authority/_source/distribution-cache.py}
        exec python3 ${./_source/transfer.py} "$@"
      '';
    };
  };
}
