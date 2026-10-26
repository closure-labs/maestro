{...}: {
  perSystem = {
    pkgs,
    ciNix,
    ...
  }: {
    packages.maestro-ci-graph-write-plans = pkgs.writeShellApplication {
      name = "maestro-ci-graph-write-plans";
      runtimeInputs = [ciNix pkgs.coreutils pkgs.git pkgs.jq];
      text = builtins.readFile ./_source/write-plans.sh;
    };
  };
}
