{...}: {
  perSystem = {
    pkgs,
    ciNix,
    ...
  }: {
    packages.maestro-ci-graph-equivalence = pkgs.writeShellApplication {
      name = "maestro-ci-graph-equivalence";
      runtimeInputs = [ciNix pkgs.coreutils pkgs.diffutils pkgs.git pkgs.gnutar pkgs.jq pkgs.python3];
      text = ''
        export MAESTRO_EQUIVALENCE_SOURCE=${./_source/equivalence.py}
        ${builtins.readFile ./_source/equivalence.sh}
      '';
    };
  };
}
