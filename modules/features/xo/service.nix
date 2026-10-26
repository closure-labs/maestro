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
      inherit (lib) mapAttrs' mkIf nameValuePair optionalAttrs optionals;
      valkeyCompat =
        if pkgs ? valkey-compat-redis
        then pkgs.valkey-compat-redis
        else if pkgs ? valkey-compat
        then pkgs.valkey-compat
        else pkgs.valkey;
      storageEnabled = cfg.storage.enableNFS || cfg.storage.enableCIFS || cfg.storage.enableVHD;
      expectedListeners =
        [{port = 80;}]
        ++ optionals cfg.tls.enable [
          {
            port = 443;
            cert = cfg.tls.cert;
            key = cfg.tls.key;
          }
        ];
      expectedMounts = {
        "/" = "${cfg.home}/xen-orchestra/@xen-orchestra/web/dist";
        "/v5" = "${cfg.home}/xen-orchestra/packages/xo-web/dist";
        "/v6" = "${cfg.home}/xen-orchestra/@xen-orchestra/web/dist";
      };
      tomlFormat = pkgs.formats.toml {};
      configFragments = {
        http.http = {
          redirectToHttps = cfg.tls.enable;
          listen = expectedListeners;
        };
        web.http.mounts = expectedMounts;
        redis.redis.socket = "/run/redis-xo/redis.sock";
        remotes.remoteOptions = {
          mountsDir = cfg.storage.mountsDir;
          useSudo = true;
        };
      };
      renderedConfigFragments =
        mapAttrs' (
          feature: value:
            nameValuePair "xo-server/config.nixos-${feature}.toml" {
              source = tomlFormat.generate "xo-server-config-nixos-${feature}.toml" value;
              mode = "0644";
            }
        )
        configFragments;
      configFragmentPaths =
        map (feature: "/etc/xo-server/config.nixos-${feature}.toml")
        (builtins.attrNames configFragments);
      startXO = pkgs.writeShellScript "xo-start" ''
        set -euo pipefail
        export HOME=${lib.escapeShellArg cfg.home}
        export NODE_ENV=production
        exec ${cfg.package}/bin/xo-server "$@"
      '';
    in {
      config = mkIf cfg.enable {
        maestro.xo.internal.configFragments = configFragments;

        users.groups.${cfg.group} = {};
        users.groups.fuse = {};
        users.users.${cfg.user} = {
          isSystemUser = true;
          description = "Xen Orchestra service account";
          # Explicit tmpfiles rules own the home; user activation otherwise chowns
          # it back to XO on every switch, defeating protected mount ancestors.
          createHome = false;
          group = cfg.group;
          home = cfg.home;
          shell = "${pkgs.shadow}/bin/nologin";
          extraGroups = ["fuse"];
        };

        services.redis = {
          package = pkgs.valkey;
          servers.xo = {
            enable = true;
            user = cfg.user;
            unixSocket = "/run/redis-xo/redis.sock";
            unixSocketPerm = 770;
            settings =
              {
                port = 0;
                databases = 16;
                maxmemory-policy = cfg.redis.maxmemoryPolicy;
              }
              // optionalAttrs (cfg.redis.maxmemory != null) {
                maxmemory = cfg.redis.maxmemory;
              };
          };
        };

        environment.etc = renderedConfigFragments;

        environment.systemPackages =
          [
            valkeyCompat
            pkgs.rsync
            pkgs.openssl
            pkgs.fuse
            pkgs.lvm2
            pkgs.ntfs3g
            pkgs.git
            pkgs.valkey
          ]
          ++ optionals cfg.storage.enableNFS [pkgs.nfs-utils]
          ++ optionals cfg.storage.enableCIFS [pkgs.cifs-utils];

        systemd.tmpfiles.rules = [
          "d ${cfg.home} 1770 root ${cfg.group} - -"
          "d ${cfg.cacheDir} 0750 ${cfg.user} ${cfg.group} - -"
          "d ${cfg.dataDir} 0750 ${cfg.user} ${cfg.group} - -"
          "d ${cfg.tempDir} 0750 ${cfg.user} ${cfg.group} - -"
          "d ${cfg.home}/.config 0750 ${cfg.user} ${cfg.group} - -"
          "d ${cfg.home}/.config/xo-server 0750 ${cfg.user} ${cfg.group} - -"
          "d /etc/xo-server 0755 root root - -"
          "d /var/lib/xo-server 0750 ${cfg.user} ${cfg.group} - -"
          "L+ ${cfg.home}/xen-orchestra - - - - ${cfg.package}/libexec/xen-orchestra"
        ];

        security.pam.loginLimits = [
          {
            domain = cfg.user;
            type = "soft";
            item = "nofile";
            value = "65536";
          }
          {
            domain = cfg.user;
            type = "hard";
            item = "nofile";
            value = "1048576";
          }
        ];

        systemd.services.xo-server = {
          description = "Xen Orchestra Server";
          after =
            [
              "systemd-tmpfiles-setup.service"
              "network-online.target"
              "redis-xo.service"
            ]
            ++ lib.optional (cfg.tls.enable && cfg.tls.autoCert) "xo-autocert.service";
          wants = [
            "network-online.target"
            "redis-xo.service"
          ];
          wantedBy = ["multi-user.target"];
          requires = ["redis-xo.service"];

          path =
            optionals (config.maestro.xo.internal.sudoWrapper != null) [config.maestro.xo.internal.sudoWrapper]
            ++ [
              pkgs.util-linux
              pkgs.git
              pkgs.openssl
              pkgs.lvm2
              pkgs.coreutils
              pkgs.xen
            ]
            ++ optionals cfg.storage.enableNFS [pkgs.nfs-utils]
            ++ optionals cfg.storage.enableCIFS [pkgs.cifs-utils];

          environment =
            cfg.extraServerEnv
            // {
              HOME = cfg.home;
              XDG_CONFIG_HOME = "${cfg.home}/.config";
              XDG_CACHE_HOME = cfg.cacheDir;
              TMPDIR = cfg.tempDir;
              NODE_ENV = "production";
              LD_LIBRARY_PATH = lib.makeLibraryPath [
                pkgs.fuse
                pkgs.stdenv.cc.cc.lib
              ];
            };

          serviceConfig = {
            EnvironmentFile = cfg.extraServerEnvFiles;
            User = cfg.user;
            Group = cfg.group;
            WorkingDirectory = "${cfg.package}/libexec/xen-orchestra";
            # tmpfiles owns the protected home/mount ancestors. StateDirectory=xo
            # would recursively give those root-owned names back to the service.
            CacheDirectory = "xo";
            LogsDirectory = "xo";
            RuntimeDirectory = "xo xo-server";
            ExecStart = startXO;
            Restart = "on-failure";
            RestartSec = "10s";
            TimeoutStartSec = "5min";
            PrivateTmp = true;
            ProtectSystem = "full";
            ProtectHome = true;
            PrivateDevices = false;
            AmbientCapabilities = ["CAP_NET_BIND_SERVICE"];
            CapabilityBoundingSet =
              ["CAP_NET_BIND_SERVICE"]
              ++ optionals storageEnabled [
                "CAP_CHOWN"
                "CAP_SETUID"
                "CAP_SETGID"
                "CAP_SETPCAP"
                "CAP_SYS_ADMIN"
                "CAP_DAC_READ_SEARCH"
                "CAP_DAC_OVERRIDE"
              ];
            ReadOnlyPaths = configFragmentPaths ++ optionals cfg.tls.enable [cfg.tls.dir];
            ReadWritePaths =
              [
                cfg.home
                cfg.cacheDir
                cfg.dataDir
                cfg.tempDir
                "/var/lib/xo-server"
                "/var/log/xo"
                "/run/lock"
                "/run/redis-xo"
              ]
              ++ optionals storageEnabled [cfg.storage.mountsDir];
            LimitNOFILE = "1048576";
          };
        };

        assertions = [
          {
            assertion = lib.all (path: lib.hasPrefix "/" path && !(lib.hasPrefix "/nix/store/" path)) cfg.extraServerEnvFiles;
            message = "maestro.xo.extraServerEnvFiles must be absolute runtime filenames outside the Nix store.";
          }
          {
            assertion = cfg.package != null;
            message = "maestro.xo.package must be configured.";
          }
        ];
      };

      options.maestro.xo.internal.sudoWrapper = lib.mkOption {
        type = lib.types.nullOr lib.types.package;
        default = null;
        internal = true;
      };

      options.maestro.xo.internal.configFragments = lib.mkOption {
        type = lib.types.attrsOf lib.types.anything;
        readOnly = true;
        internal = true;
      };
    };
}
