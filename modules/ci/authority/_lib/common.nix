{
  pkgs,
  ciNix,
}: let
  publicCacheWorker = pkgs.writeText "maestro-public-cache-worker.py" (builtins.replaceStrings
    ["@LIBCURL@"]
    ["${pkgs.curl.out}/lib/libcurl.so.4"]
    (builtins.readFile ../_source/decisions/public_cache_worker.py));

  mkCommand = {
    name,
    prefix ? "",
    runtimeInputs ? [],
    source,
  }:
    pkgs.writeShellApplication {
      inherit runtimeInputs;
      name = "maestro-ci-${name}";
      text = builtins.readFile ../_source/command-preamble.sh + prefix + builtins.readFile source;
    };

  boundedGh = pkgs.writeShellApplication {
    name = "gh";
    runtimeInputs = [pkgs.python3];
    text =
      builtins.replaceStrings
      ["@GH@" "@PYTHON@" "@OPERATIONS@"]
      ["${pkgs.gh}/bin/gh" "${pkgs.python3}/bin/python3" "${../_source/decisions/operations.py}"]
      (builtins.readFile ../_source/bounded-gh.sh);
  };

  commonInputs = with pkgs; [
    bash
    coreutils
    findutils
    git
    boundedGh
    gnugrep
    gnused
    jq
    ciNix
  ];

  spdxSchema = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json";
    hash = "sha256-I5IIt6woezz12amvI/nWmGOXEQKl4Vh6J6OYtDSQuJs=";
  };

  validatePlan = mkCommand {
    name = "validate-plan";
    prefix = ''
      MAESTRO_CI_PLAN_SCHEMA="''${MAESTRO_CI_PLAN_SCHEMA:-${../_source/qualification-plan.schema.json}}"
      export MAESTRO_CI_PLAN_SCHEMA
    '';
    runtimeInputs = commonInputs ++ [pkgs.check-jsonschema];
    source = ../_source/validate-plan.sh;
  };

  classifyPaths = mkCommand {
    name = "classify-paths";
    runtimeInputs = commonInputs;
    source = ../_source/classify-paths.sh;
  };
in {inherit mkCommand commonInputs spdxSchema boundedGh publicCacheWorker validatePlan classifyPaths;}
