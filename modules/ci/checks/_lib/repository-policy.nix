{
  lib,
  pkgs,
  source,
}: let
  read = relative: builtins.readFile "${source}/${relative}";
  staticDefinitions = builtins.fromJSON (read "modules/ci/checks/_lib/repository-rules.json");
  validKinds = ["contains" "excludes" "absent"];
  validDefinition = rule:
    rule ? kind
    && builtins.elem rule.kind validKinds
    && rule ? path
    && builtins.isString rule.path
    && rule ? message
    && builtins.isString rule.message
    && (rule.kind == "absent" || (rule ? needle && builtins.isString rule.needle));
  evaluateDefinition = rule: {
    ok =
      if rule.kind == "absent"
      then !builtins.pathExists "${source}/${rule.path}"
      else if rule.kind == "contains"
      then lib.hasInfix rule.needle (read rule.path)
      else !lib.hasInfix rule.needle (read rule.path);
    inherit (rule) message;
  };
  staticRules = assert lib.assertMsg
  (builtins.all validDefinition staticDefinitions)
  "modules/ci/checks/_lib/repository-rules.json contains an invalid rule";
    map evaluateDefinition staticDefinitions;

  # Source packaging is declared beside each owner. Native wrapper files must
  # remain represented in the owner package definitions and common helper.
  automationDirectories = [
    "modules/ci/authority/_source"
    "modules/ci/checks/_source"
    "modules/ci/security/_source"
    "modules/ci/inventory/_source"
    "modules/features/development/_source"
    "modules/features/installer/_source"
    "modules/features/xcp-ng/template/_source"
    "modules/ci/graph/_source"
    "modules/release/publication/_source"
  ];
  automationDefinition = lib.concatStringsSep "\n" (map read [
    "modules/ci/authority/_lib/common.nix"
    "modules/ci/authority/_lib/commands.nix"
    "modules/ci/checks/_lib/commands.nix"
    "modules/ci/graph/_lib/commands.nix"
    "modules/ci/inventory/_lib/commands.nix"
    "modules/ci/security/_lib/commands.nix"
    "modules/features/development/_lib/commands.nix"
    "modules/features/installer/_lib/commands.nix"
    "modules/features/xcp-ng/template/_lib/commands.nix"
    "modules/release/consumer/_lib/commands.nix"
    "modules/release/publication/_lib/commands.nix"
  ]);
  automationWrapperRules = lib.concatMap (directory: let
    scripts = builtins.readDir "${source}/${directory}";
    names = builtins.filter (name: lib.hasSuffix ".sh" name && scripts.${name} == "regular") (builtins.attrNames scripts);
  in
    map (script: {
      # Build/install/boot evidence leaves are independently packaged by their
      # feature modules; the migrated automation names keep native wrappers.
      ok =
        lib.hasInfix "/${script}" automationDefinition
        || builtins.elem script ["build.sh" "bootstrap.sh" "bootstrap-key.sh" "install-maestro.sh" "deploy-template.sh" "plan.sh" "nix.sh" "assets.sh" "equivalence.sh" "write-plans.sh"];
      message = "${directory}/${script} must be wrapped by its owning native package";
    })
    names)
  automationDirectories;

  workflowDirectory = builtins.readDir "${source}/.github/workflows";
  workflowFiles = lib.sort builtins.lessThan (
    builtins.filter
    (name:
      (lib.hasSuffix ".yml" name || lib.hasSuffix ".yaml" name)
      && workflowDirectory.${name} == "regular")
    (builtins.attrNames workflowDirectory)
  );
  workflowRunRules =
    map (workflow: let
      runLines =
        builtins.filter
        (line: builtins.match "[[:space:]]*run:.*" line != null)
        (lib.splitString "\n" (read ".github/workflows/${workflow}"));
    in {
      ok =
        (workflow
          == "decision-events.yml"
          && read ".github/workflows/${workflow}" == read "modules/ci/checks/_lib/signal-relay.yml")
        || builtins.all
        (line: (lib.hasInfix "--option 'packages:pkgs!' ''" line
          && (builtins.match
            "[[:space:]]*run: nix run --accept-flake-config \\.#devenv -- tasks run .*ci:repository-audit[[:space:]]*"
            line
            != null
            || builtins.match
            "[[:space:]]*run: nix run --accept-flake-config \\.#devenv -- tasks run --mode single .* [a-z0-9:_-]+[[:space:]]*"
            line
            != null)))
        runLines;
      message = ".github/workflows/${workflow} must run declared devenv tasks with the development package set disabled";
    })
    workflowFiles;

  version = lib.removeSuffix "\n" (read "VERSION");
  rules =
    [
      {
        ok = builtins.match "[0-9]+\\.[0-9]+\\.[0-9]+(-dev\\.[0-9]+)?" version != null;
        message = "VERSION must be a stable or development semantic version";
      }
    ]
    ++ staticRules
    ++ automationWrapperRules
    ++ workflowRunRules;
  failures = map (rule: rule.message) (builtins.filter (rule: !rule.ok) rules);
in
  assert lib.assertMsg (failures == [])
  ("Repository policy violations:\n- " + lib.concatStringsSep "\n- " failures);
    pkgs.runCommandLocal "maestro-repository-policy" {
      allowSubstitutes = true;
      nativeBuildInputs = [pkgs.bash pkgs.findutils pkgs.gnugrep];
    } ''
      cd ${source}
      bash ${../_tests/repository-identity.sh}
      touch "$out"
    ''
