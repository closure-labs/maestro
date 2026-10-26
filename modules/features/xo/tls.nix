{...}: {
  den.aspects.xo.nixos = {
    key = "modules/features/xo/tls/nixos";
    imports = [
      (
        # SPDX-License-Identifier: Apache-2.0
        {
          config,
          lib,
          pkgs,
          ...
        }: let
          cfg = config.maestro.xo;
          enabled = cfg.enable && cfg.tls.enable && cfg.tls.autoCert;
          generateCertificate = pkgs.writeShellApplication {
            name = "xo-generate-certificate";
            runtimeInputs = [pkgs.coreutils pkgs.openssl];
            text = ''
              export MAESTRO_XO_TLS_CERT=${lib.escapeShellArg cfg.tls.cert}
              export MAESTRO_XO_TLS_KEY=${lib.escapeShellArg cfg.tls.key}
              export MAESTRO_XO_TLS_DIR=${lib.escapeShellArg cfg.tls.dir}
              export MAESTRO_XO_HOSTNAME=${lib.escapeShellArg config.networking.hostName}
              export MAESTRO_XO_HTTP_HOST=${lib.escapeShellArg cfg.httpHost}
              export MAESTRO_XO_USER=${lib.escapeShellArg cfg.user}
              export MAESTRO_XO_GROUP=${lib.escapeShellArg cfg.group}
              ${builtins.readFile ./_source/autocert.sh}
            '';
          };
        in {
          config = lib.mkIf enabled {
            systemd.tmpfiles.rules = [
              "d ${cfg.tls.dir} 0755 root root - -"
            ];
            systemd.services.xo-autocert = {
              description = "Generate the XO TLS certificate";
              wantedBy = ["multi-user.target"];
              after = [
                "local-fs.target"
                "systemd-tmpfiles-setup.service"
              ];
              before = ["xo-server.service"];
              serviceConfig = {
                Type = "oneshot";
                RemainAfterExit = true;
                ExecStart = lib.getExe generateCertificate;
                User = "root";
                Group = "root";
              };
            };
          };
        }
      )
    ];
  };
}
