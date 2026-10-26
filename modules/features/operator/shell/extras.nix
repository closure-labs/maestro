{...}: {
  den.aspects.operator.homeManager = {
    key = "modules/features/operator/shell/extras/homeManager";
    imports = [
      (
        # SPDX-License-Identifier: Apache-2.0
        # Shell tooling extras
        {
          lib,
          pkgs,
          osConfig,
          ...
        }: let
          cfg = osConfig.maestro.operator;
          fdSearchCmd = "${pkgs.fd}/bin/fd --type f --hidden --follow --exclude .git";
        in {
          programs.direnv = lib.mkIf cfg.enableExtras {
            enable = true;
            nix-direnv.enable = true;
            enableBashIntegration = false;
            enableZshIntegration = true;
          };

          programs.zoxide = lib.mkIf cfg.enableExtras {
            enable = true;
            enableBashIntegration = false;
            enableZshIntegration = true;
          };

          programs.fzf = lib.mkIf cfg.enableExtras {
            enable = true;
            enableBashIntegration = false;
            enableZshIntegration = true;
            defaultCommand = fdSearchCmd;
            fileWidgetCommand = fdSearchCmd;
            defaultOptions = [
              "--height 40%"
              "--layout=reverse"
              "--border"
            ];
          };

          programs.oh-my-posh = lib.mkIf cfg.enableExtras {
            enable = true;
            enableBashIntegration = false;
            enableZshIntegration = true;
            useTheme = "night-owl";
          };
        }
      )
    ];
  };
}
