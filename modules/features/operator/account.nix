{...}: {
  den.aspects.operator.nixos =
    # SPDX-License-Identifier: Apache-2.0
    {
      config,
      inputs,
      lib,
      pkgs,
      ...
    }: let
      cfg = config.maestro.operator;
      inherit (lib) mkIf mkOption types;
      resolvePackage = item:
        lib.attrByPath
        (lib.splitString "." item)
        (throw "Maestro package '${item}' was not found in pkgs")
        pkgs;
      mkServiceEnable = name:
        lib.setAttrByPath
        (lib.splitString "." name ++ ["enable"])
        true;
      maestroctl = pkgs.callPackage ./cli/_source/package/package.nix {
        repoRootDefault = cfg.repoDir;
      };
      maestroMenu = pkgs.callPackage ./menu/_source/frontend/package.nix {
        repoRootDefault = cfg.repoDir;
      };
    in {
      options.maestro.operator = {
        username = mkOption {
          type = types.str;
          default = "maestro";
          readOnly = true;
          description = "The fixed Maestro operator account.";
        };
        repoDir = mkOption {
          type = types.str;
          default = "/home/maestro/maestro";
          description = "Path to the Maestro checkout on the appliance.";
        };
        gitName = mkOption {
          type = types.str;
          default = "Maestro Admin";
          description = "Git author name used by operator tooling.";
        };
        gitEmail = mkOption {
          type = types.str;
          default = "maestro@maestro";
          description = "Git author email used by operator tooling.";
        };
        sshKeys = mkOption {
          type = types.listOf types.str;
          default = [];
          description = "SSH public keys authorized for the maestro operator.";
        };
        enableExtras = lib.mkEnableOption "the expanded operator shell toolset";
        developmentMode = lib.mkEnableOption "development packages for working on Maestro";
        menuAutoStart = lib.mkEnableOption "automatic maestro-menu startup for SSH sessions";
        sudoNoPassword = mkOption {
          type = types.bool;
          default = true;
          description = "Whether the operator may use sudo without a password.";
        };
        systemPackages = mkOption {
          type = types.listOf types.str;
          default = [];
          description = "Additional system package attribute paths.";
        };
        userPackages = mkOption {
          type = types.listOf types.str;
          default = [];
          description = "Additional Home Manager package attribute paths.";
        };
        menu = {
          extraSystemPackages = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "System packages managed by maestro-menu.";
          };
          extraUserPackages = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "User packages managed by maestro-menu.";
          };
          enabledServices = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "NixOS service option paths enabled by maestro-menu.";
          };
        };
      };

      config = lib.mkMerge [
        {
          users.mutableUsers = true;
          users.users.${cfg.username} = {
            isNormalUser = true;
            description = "Maestro operator";
            home = "/home/${cfg.username}";
            createHome = true;
            group = "users";
            extraGroups = [
              "wheel"
              "systemd-journal"
            ];
            hashedPassword = "!";
            openssh.authorizedKeys.keys = cfg.sshKeys;
            shell =
              if cfg.enableExtras
              then pkgs.zsh
              else pkgs.bashInteractive;
          };

          services = lib.mkMerge (
            [
              {
                openssh = {
                  enable = true;
                  openFirewall = false;
                  settings = {
                    PermitRootLogin = "no";
                    PasswordAuthentication = false;
                    KbdInteractiveAuthentication = false;
                    PubkeyAuthentication = true;
                    AllowUsers = [cfg.username];
                    X11Forwarding = false;
                    PermitEmptyPasswords = false;
                    Protocol = 2;
                    ClientAliveInterval = 300;
                    ClientAliveCountMax = 2;
                  };
                };
              }
            ]
            ++ map mkServiceEnable cfg.menu.enabledServices
          );

          security.sudo = {
            enable = true;
            wheelNeedsPassword = !cfg.sudoNoPassword;
            extraRules = lib.optionals cfg.sudoNoPassword [
              {
                users = [cfg.username];
                commands = [
                  {
                    command = "ALL";
                    options = ["NOPASSWD"];
                  }
                ];
              }
            ];
          };

          environment.shells = [pkgs.bashInteractive] ++ lib.optional cfg.enableExtras pkgs.zsh;
          programs = {
            bash.completion.enable = true;
            zsh.enable = cfg.enableExtras;
            git.enable = true;
            direnv = mkIf cfg.enableExtras {
              enable = true;
              nix-direnv.enable = true;
            };
          };

          environment.systemPackages =
            map resolvePackage (cfg.systemPackages ++ cfg.menu.extraSystemPackages)
            ++ [
              maestroctl
              maestroMenu
              pkgs.nh
            ];

          nixpkgs.config.allowUnfree = true;

          systemd.tmpfiles.rules = [
            "d /var/lib/maestro 0755 root root - -"
            "d /home/${cfg.username}/.ssh 0700 ${cfg.username} users - -"
          ];

          systemd.services.maestro-rebuild = {
            description = "Apply a queued Maestro rebuild on boot";
            wantedBy = ["multi-user.target"];
            wants = ["network-online.target"];
            after = ["network-online.target"];
            unitConfig.ConditionPathExists = "/var/lib/maestro/rebuild-on-boot.env";
            serviceConfig = {
              Type = "oneshot";
              User = "root";
            };
            script = ''
              set -euo pipefail
              queue_file=/var/lib/maestro/rebuild-on-boot.env
              # shellcheck source=/var/lib/maestro/rebuild-on-boot.env
              . "$queue_file"
              [ -n "''${repo_root:-}" ] || {
                echo "Queued Maestro rebuild is missing repo_root." >&2
                exit 1
              }
              MAESTRO_SYSTEM_ROOT="$repo_root" ${maestroctl}/bin/maestroctl apply
              rm -f "$queue_file"
            '';
          };
        }
        (mkIf cfg.developmentMode {
          environment.systemPackages = with pkgs; [
            devenv
            cargo
            clippy
            rust-analyzer
            rustc
            rustfmt
            rustup
            pkg-config
            corepack
            nodejs
            pnpm
            yarn
            redis
            valkey
          ];
        })
      ];
    };
}
