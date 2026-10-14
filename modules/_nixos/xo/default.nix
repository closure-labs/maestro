# SPDX-License-Identifier: Apache-2.0
{
  config,
  inputs,
  lib,
  ...
}: let
  inherit (lib) mkOption types;
in {
  imports = [
    ./service.nix
    ./tls.nix
    ./storage.nix
    ./file-restore.nix
  ];

  options.maestro.xo = {
    enable = lib.mkEnableOption "Xen Orchestra";
    channel = mkOption {
      type = types.enum [
        "latest"
        "stable"
        "rolling"
      ];
      default = "latest";
      description = "xo-nixpkg release channel used by the default Xen Orchestra package.";
    };
    package = mkOption {
      type = types.package;
      default = inputs.xen-orchestra-ce.packages.x86_64-linux.${config.maestro.xo.channel};
      defaultText = lib.literalExpression "inputs.xen-orchestra-ce.packages.x86_64-linux.\${config.maestro.xo.channel}";
      description = "Xen Orchestra package to run.";
    };
    user = mkOption {
      type = types.str;
      default = "xo";
      description = "System user that runs Xen Orchestra.";
    };
    group = mkOption {
      type = types.str;
      default = "xo";
      description = "Primary group for the Xen Orchestra service user.";
    };
    home = mkOption {
      type = types.str;
      default = "/var/lib/xo";
      description = "XO service home directory.";
    };
    cacheDir = mkOption {
      type = types.str;
      default = "${config.maestro.xo.home}/.cache";
      description = "XO cache directory.";
    };
    dataDir = mkOption {
      type = types.str;
      default = "${config.maestro.xo.home}/data";
      description = "XO data directory.";
    };
    tempDir = mkOption {
      type = types.str;
      default = "${config.maestro.xo.home}/tmp";
      description = "XO temporary directory exposed to Node.js through TMPDIR.";
    };
    httpHost = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = "Address used in automatically generated certificates.";
    };
    extraServerEnv = mkOption {
      type = types.attrsOf types.str;
      default = {};
      description = "Non-secret environment variables for xo-server. Use extraServerEnvFiles for secrets.";
    };
    extraServerEnvFiles = mkOption {
      type = types.listOf types.str;
      default = [];
      example = ["/run/secrets/xo.env"];
      description = "Absolute runtime environment filenames for XO secrets. File contents must never be passed through Nix evaluation.";
    };
    redis = {
      maxmemory = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "256mb";
        description = "Optional Valkey memory limit for XO.";
      };
      maxmemoryPolicy = mkOption {
        type = types.str;
        default = "noeviction";
        description = "Valkey eviction policy for the XO database.";
      };
    };
    tls = {
      enable = lib.mkEnableOption "TLS for XO";
      autoCert = lib.mkEnableOption "automatic self-signed XO certificates";
      dir = mkOption {
        type = types.str;
        default = "/etc/ssl/xo";
        description = "XO TLS directory.";
      };
      cert = mkOption {
        type = types.str;
        default = "${config.maestro.xo.tls.dir}/certificate.pem";
        description = "XO TLS certificate path.";
      };
      key = mkOption {
        type = types.str;
        default = "${config.maestro.xo.tls.dir}/key.pem";
        description = "XO TLS key path.";
      };
    };
    storage = {
      enableNFS = mkOption {
        type = types.bool;
        default = true;
        description = "Enable NFS remote storage support.";
      };
      enableCIFS = mkOption {
        type = types.bool;
        default = true;
        description = "Enable CIFS remote storage support.";
      };
      enableVHD = mkOption {
        type = types.bool;
        default = true;
        description = "Enable VHD/VHDX access through libvhdi.";
      };
      mountsDir = mkOption {
        type = types.str;
        default = "/var/lib/xo/mounts";
        description = "Root directory for XO-managed mounts.";
      };
      libvhdiPackage = mkOption {
        type = types.package;
        default = inputs.xen-orchestra-ce.packages.x86_64-linux.libvhdi;
        description = "libvhdi implementation used by XO.";
      };
    };
  };
}
