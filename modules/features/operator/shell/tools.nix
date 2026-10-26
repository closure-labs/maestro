{...}: {
  den.aspects.operator.homeManager =
    # SPDX-License-Identifier: Apache-2.0
    # Extra tooling configuration
    {
      lib,
      pkgs,
      osConfig,
      ...
    }: let
      cfg = osConfig.maestro.operator;
    in {
      programs.bat = lib.mkIf cfg.enableExtras {
        enable = true;
        config = {
          theme = "Dracula";
          style = "changes,header";
          map-syntax = [
            "*.conf:INI"
            ".ignore:Git Ignore"
          ];
        };
      };

      programs.git = {
        enable = true;
        settings =
          {
            user.name = cfg.gitName;
            user.email = cfg.gitEmail;
            init.defaultBranch = "main";
            pull.rebase = true;
            merge.conflictstyle = "diff3";
            diff.colorMoved = "default";
          }
          // lib.optionalAttrs cfg.enableExtras {
            core.pager = "${pkgs.delta}/bin/delta";
            delta = {
              navigate = true;
              line-numbers = true;
              syntax-theme = "Dracula";
            };
          };
      };
    };
}
