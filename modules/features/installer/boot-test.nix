{...}: {
  perSystem = {
    pkgs,
    config,
    lib,
    ...
  }: let
    pythonSource = lib.fileset.toSource {
      root = ../../ci/graph/_source;
      fileset = lib.fileset.unions [../../ci/graph/_source/graph.py ../../ci/graph/_source/transfer.py];
    };
  in {
    packages.maestro-ci-boot-evidence = pkgs.writeShellApplication {
      name = "maestro-ci-boot-evidence";
      runtimeInputs = [pkgs.python3 config.packages.maestro-ci-verify-inventory];
      text = ''
        export PYTHONDONTWRITEBYTECODE=1
        export PYTHONPATH=${pythonSource}
        export MAESTRO_BOOT_POLICY_SHA256=${import ./_lib/boot-policy.nix}
        export MAESTRO_BOOT_VERIFIER=${./_source/boot-media.sh}
        exec python3 ${./_source/boot-evidence.py}
      '';
    };
  };
}
