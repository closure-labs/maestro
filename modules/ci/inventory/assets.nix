{...}: {
  perSystem = {
    pkgs,
    ciNix,
    config,
    ...
  }: {
    packages.maestro-ci-inventory-assets = pkgs.writeShellApplication {
      name = "maestro-ci-inventory-assets";
      runtimeInputs = [pkgs.git ciNix pkgs.coreutils pkgs.gnugrep pkgs.jq pkgs.check-jsonschema config.packages.maestro-ci-verify-state config.packages.maestro-ci-verify-inventory config.packages.maestro-ci-security-inventory];
      text = ''
        export MAESTRO_CI_TIME=${pkgs.time}/bin/time
        ${builtins.readFile ../checks/_source/measure-phase.sh}
        export MAESTRO_SPDX_SCHEMA=${pkgs.fetchurl {
          url = "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json";
          hash = "sha256-I5IIt6woezz12amvI/nWmGOXEQKl4Vh6J6OYtDSQuJs=";
        }}
        ${builtins.readFile ./_source/assets.sh}
      '';
    };
  };
}
