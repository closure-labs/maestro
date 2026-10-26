{...}: {
  den.aspects.operator.homeManager = {
    key = "modules/features/operator/shell/bash/homeManager";
    imports = [
      (
        # SPDX-License-Identifier: Apache-2.0
        # Bash configuration
        {
          config,
          lib,
          osConfig,
          ...
        }: let
          cfg = osConfig.maestro.operator;
        in {
          programs = {
            bash = {
              enable = true;
              enableCompletion = true;
              historySize = 50000;
              historyFile = "${config.home.homeDirectory}/.bash_history";
              historyFileSize = 100000;
              historyControl = [
                "ignoredups"
                "ignorespace"
                "erasedups"
              ];
              historyIgnore = [
                "exit"
                "history"
              ];
              shellOptions = [
                "histappend"
                "cmdhist"
                "checkwinsize"
                "extglob"
                "globstar"
                "checkjobs"
              ];
              shellAliases = {
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
              };
              sessionVariables = {
                HISTTIMEFORMAT = "%F %T ";
              };
              initExtra = ''
                if [[ -z "''${PROMPT_COMMAND:-}" ]]; then
                  PROMPT_COMMAND="history -a; history -n"
                else
                  PROMPT_COMMAND="history -a; history -n; $PROMPT_COMMAND"
                fi
              '';
              profileExtra = lib.optionalString cfg.menuAutoStart ''
                if [[ $- == *i* ]] && [[ -n "''${SSH_TTY:-}" ]] && [[ -t 0 ]] && [[ -t 1 ]] && [[ -z "''${MAESTRO_TUI_BYPASS:-}" ]] && [[ -z "''${MAESTRO_TUI_ACTIVE:-}" ]]; then
                  export MAESTRO_TUI_ACTIVE=1
                  export MAESTRO_SYSTEM_ROOT="''${MAESTRO_SYSTEM_ROOT:-${cfg.repoDir}}"
                  exec maestro-menu
                fi
              '';
            };

            readline = {
              enable = true;
              variables = {
                "colored-completion-prefix" = true;
                "colored-stats" = true;
                "completion-ignore-case" = true;
                "mark-symlinked-directories" = true;
                "show-all-if-ambiguous" = true;
                "visible-stats" = true;
              };
              bindings = {
                "\\e[A" = "history-search-backward";
                "\\e[B" = "history-search-forward";
                "\\e[5~" = "history-search-backward";
                "\\e[6~" = "history-search-forward";
              };
            };
          };
        }
      )
    ];
  };
}
