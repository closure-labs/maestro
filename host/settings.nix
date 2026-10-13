# SPDX-License-Identifier: Apache-2.0
# Hand-maintained settings for the single Maestro appliance.
{lib, ...}: {
  networking.hostName = "maestro";
  time.timeZone = "America/Chicago";
  system.stateVersion = "26.05";

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  maestro.operator = {
    managementCIDRs = ["192.168.0.0/16"];
    repoDir = "/home/maestro/maestro";
    gitName = "Maestro Admin";
    gitEmail = "maestro@maestro";
    sshKeys = lib.mkDefault [];
    enableExtras = lib.mkDefault false;
    developmentMode = lib.mkDefault false;
    menuAutoStart = false;
    sudoNoPassword = true;
    systemPackages = [];
    userPackages = [];
  };

  maestro.xo = {
    enable = true;
    httpHost = "0.0.0.0";
    tls = {
      enable = true;
      autoCert = true;
    };
    storage = {
      enableNFS = true;
      enableCIFS = true;
      enableVHD = true;
      mountsDir = "/var/lib/xo/mounts";
    };
  };
}
