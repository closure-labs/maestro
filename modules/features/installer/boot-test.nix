{...}: {
  perSystem = {
    pkgs,
    config,
    ...
  }: {
    packages.maestro-ci-boot-evidence = pkgs.writeShellApplication {
      name = "maestro-ci-boot-evidence";
      runtimeInputs = [pkgs.python3 config.packages.maestro-ci-verify-inventory];
      text = ''
        export PYTHONDONTWRITEBYTECODE=1
        export PYTHONPATH=${../../ci/graph/_source}
        export MAESTRO_BOOT_POLICY_SHA256=${import ./_lib/boot-policy.nix}
        export MAESTRO_BOOT_VERIFIER=${./_source/boot-media.sh}
        exec python3 ${./_source/boot-evidence.py}
      '';
    };
  };
}
