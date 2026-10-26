{...}: {
  den.aspects.operator.homeManager =
    # SPDX-License-Identifier: Apache-2.0
    # Zsh + oh-my-zsh configuration
    {
      config,
      lib,
      pkgs,
      osConfig,
      ...
    }: let
      cfg = osConfig.maestro.operator;
    in {
      programs.zsh = lib.mkIf cfg.enableExtras {
        enable = true;
        enableCompletion = true;
        autosuggestion.enable = true;
        syntaxHighlighting.enable = true;
        loginExtra = lib.optionalString cfg.menuAutoStart ''
          if [[ -n "''${SSH_TTY:-}" ]] && [[ -o interactive ]] && [[ -t 0 ]] && [[ -t 1 ]] && [[ -z "''${MAESTRO_TUI_BYPASS:-}" ]] && [[ -z "''${MAESTRO_TUI_ACTIVE:-}" ]]; then
            export MAESTRO_TUI_ACTIVE=1
            export MAESTRO_SYSTEM_ROOT="''${MAESTRO_SYSTEM_ROOT:-${cfg.repoDir}}"
            exec maestro-menu
          fi
        '';

        history = {
          size = 50000;
          path = "${config.home.homeDirectory}/.zsh_history";
          ignoreDups = true;
          ignoreAllDups = true;
          extended = true;
          share = true;
        };

        oh-my-zsh = {
          enable = true;
          plugins = [
            "git"
            "sudo"
            "docker"
            "kubectl"
            "systemd"
            "ssh-agent"
            "command-not-found"
            "colored-man-pages"
            "history-substring-search"
          ];
        };

        shellAliases =
          {
            ".." = "cd ..";
            "..." = "cd ../..";

            gs = "git status";
            ga = "git add";
            gc = "git commit";
            gp = "git push";
            gl = "git log --oneline --graph --decorate";
            gd = "git diff";

            syslog = "journalctl -xe";
            sysfail = "systemctl --failed";
            sysrestart = "sudo systemctl restart";
            sysstatus = "sudo systemctl status";
            menu = "maestro-menu";
          }
          // lib.optionalAttrs cfg.enableExtras {
            ls = "eza --icons --group-directories-first";
            ll = "eza -l --icons --group-directories-first --git";
            la = "eza -la --icons --group-directories-first --git";
            lt = "eza --tree --level=2 --icons";
            cat = "bat --style=changes,header";
            catn = "bat --style=numbers,changes,header";
            cd = "z";
            cdi = "zi";
          };

        initContent = ''
          export FZF_DEFAULT_OPTS="--height 40% --layout=reverse --border --preview '${pkgs.bat}/bin/bat --color=always --style=numbers --line-range=:500 {}'"

          bindkey '^[[A' history-substring-search-up
          bindkey '^[[B' history-substring-search-down
        '';

        defaultKeymap = "emacs";
      };
    };
}
