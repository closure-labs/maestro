{...}: {
  den.aspects.xo.nixos =
    # SPDX-License-Identifier: Apache-2.0
    {
      config,
      lib,
      pkgs,
      ...
    }: let
      cfg = config.maestro.xo;
      storage = cfg.storage;
      enabled = cfg.enable && (storage.enableNFS || storage.enableCIFS || storage.enableVHD);
      allowedMountTypes =
        lib.optional storage.enableCIFS "cifs"
        ++ lib.optionals storage.enableNFS [
          "nfs"
          "nfs4"
        ];
      mountGuard = pkgs.writeShellApplication {
        name = "xo-mount-guard";
        runtimeInputs = [pkgs.python3];
        text = ''
          exec python3 ${./_source/mount-guard.py} "$@"
        '';
      };
      storageHelper = pkgs.writeShellApplication {
        name = "xo-storage-helper";
        runtimeInputs =
          [
            pkgs.coreutils
            pkgs.util-linux
          ]
          ++ lib.optionals storage.enableNFS [pkgs.nfs-utils]
          ++ lib.optionals storage.enableCIFS [pkgs.cifs-utils]
          ++ lib.optionals storage.enableVHD [storage.libvhdiPackage];
        text = ''
          export MAESTRO_XO_MOUNTS_DIR=${lib.escapeShellArg storage.mountsDir}
          export MAESTRO_XO_DATA_DIR=${lib.escapeShellArg cfg.dataDir}
          export MAESTRO_XO_TEMP_DIR=${lib.escapeShellArg cfg.tempDir}
          export MAESTRO_XO_USER=${lib.escapeShellArg cfg.user}
          export MAESTRO_XO_MOUNT_GUARD=${mountGuard}/bin/xo-mount-guard
          export MAESTRO_XO_CREDENTIALS_DIR=/run/maestro-xo-cifs-credentials
          export MAESTRO_XO_ALLOWED_MOUNT_TYPES=${lib.escapeShellArg (lib.concatStringsSep " " allowedMountTypes)}
          export MAESTRO_XO_ENABLE_CIFS=${lib.boolToString storage.enableCIFS}
          export MAESTRO_XO_ENABLE_VHD=${lib.boolToString storage.enableVHD}
          ${builtins.readFile ./_source/storage-helper.sh}
        '';
      };
      sudoCommand = pkgs.writeShellApplication {
        name = "sudo";
        runtimeInputs = [storageHelper];
        text = ''
          export MAESTRO_XO_STORAGE_HELPER=${storageHelper}/bin/xo-storage-helper
          export MAESTRO_XO_SUDO=/run/wrappers/bin/sudo
          ${builtins.readFile ./_source/sudo-wrapper.sh}
        '';
      };
      cifsProbe = pkgs.writeShellScriptBin "mount.cifs" ''
        if [ "$#" -eq 1 ] && { [ "$1" = -V ] || [ "$1" = --version ]; }; then
          echo "mount.cifs version ${pkgs.cifs-utils.version or "unknown"}"
          exit 0
        fi
        exec ${pkgs.cifs-utils}/bin/mount.cifs "$@"
      '';
      commandWrapper = pkgs.symlinkJoin {
        name = "xo-storage-command-wrapper";
        paths = [sudoCommand] ++ lib.optional storage.enableCIFS cifsProbe;
      };
    in {
      config = lib.mkIf enabled {
        maestro.xo.internal.sudoWrapper = commandWrapper;

        programs.fuse.userAllowOther = true;
        boot.kernelModules =
          ["fuse"]
          ++ lib.optionals storage.enableNFS [
            "nfs"
            "nfsv4"
          ]
          ++ lib.optional storage.enableCIFS "cifs";
        boot.supportedFilesystems =
          lib.optionals storage.enableNFS [
            "nfs"
            "nfs4"
          ]
          ++ lib.optional storage.enableCIFS "cifs";

        services.rpcbind.enable = storage.enableNFS;
        services.nfs.server.enable = false;

        environment.systemPackages = lib.optional storage.enableVHD storage.libvhdiPackage;
        systemd.tmpfiles.rules =
          [
            "d ${storage.mountsDir} 1770 root ${cfg.group} - -"
            "d /run/maestro-xo-cifs-credentials 0700 root root - -"
          ]
          ++ lib.optionals storage.enableNFS [
            "d /var/lib/nfs 0755 root root - -"
            "d /var/lib/nfs/sm 0755 root root - -"
            "d /var/lib/nfs/sm.bak 0755 root root - -"
          ];

        security.sudo = {
          enable = true;
          extraConfig = ''
            Defaults:${cfg.user} !use_pty,!log_subcmds,!syslog
          '';
          extraRules = [
            {
              users = [cfg.user];
              commands = [
                {
                  command = "${storageHelper}/bin/xo-storage-helper";
                  options = ["NOPASSWD"];
                }
              ];
            }
          ];
        };

        systemd.services.xo-sudo-init = {
          description = "Initialize sudo for the XO user";
          wantedBy = ["multi-user.target"];
          after = ["local-fs.target"];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = pkgs.writeShellScript "xo-sudo-init" ''
              install -d -m 0700 -o root -g root /var/db/sudo/lectured
              install -m 0600 -o root -g root /dev/null /var/db/sudo/lectured/${cfg.user}
            '';
          };
        };

        assertions = [
          {
            assertion = builtins.elem "fuse" config.users.users.${cfg.user}.extraGroups;
            message = "The XO service user must belong to the fuse group.";
          }
        ];
      };
    };
}
