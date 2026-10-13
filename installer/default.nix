# SPDX-License-Identifier: Apache-2.0
{
  applianceToplevel,
  config,
  lib,
  modulesPath,
  maestroMenu,
  pkgs,
  xenOrchestraCe,
  ...
}: let
  installMaestro = pkgs.writeShellApplication {
    name = "install-maestro";
    runtimeInputs = with pkgs; [
      coreutils
      dosfstools
      e2fsprogs
      findutils
      git
      openssh
      gnugrep
      gnused
      gptfdisk
      nixos-install-tools
      parted
      systemd
      util-linux
    ];
    text = builtins.readFile ./install-maestro.sh;
  };
  enrollBootstrapKey = pkgs.writeShellApplication {
    name = "maestro-enroll-bootstrap-key";
    runtimeInputs = [pkgs.coreutils pkgs.openssh];
    text = builtins.readFile ./bootstrap-key.sh;
  };
in {
  imports = [
    (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix")
  ];

  image.baseName = lib.mkForce "maestro-installer";
  isoImage = {
    squashfsCompression = "zstd -Xcompression-level 1";
    volumeID = "MAESTRO_INSTALL";

    # Seed the installer store with the complete generic appliance closure and
    # its two largest first-party outputs. The generated hardware and temporary
    # Packer policy still produce a few small machine-specific derivations, but
    # nixos-install can copy the expensive runtime closure from the ISO.
    storeContents = [
      applianceToplevel
      maestroMenu
      xenOrchestraCe
    ];
  };

  assertions = [
    {
      assertion = config.isoImage.squashfsCompression == "zstd -Xcompression-level 1";
      message = "Maestro installer SquashFS compression must remain zstd level 1";
    }
  ];

  networking.hostName = "maestro-installer";
  networking.firewall.allowedTCPPorts = [22];

  boot.kernelParams = [
    "console=tty0"
    "console=hvc0"
  ];
  boot.zfs.forceImportRoot = false;

  users = {
    mutableUsers = true;
    users.maestro = {
      isNormalUser = true;
      description = "Temporary Maestro Packer installer";
      group = "users";
      extraGroups = ["wheel"];
      hashedPassword = "!";
      openssh.authorizedKeys.keyFiles = [];
    };
  };

  security.sudo = {
    enable = true;
    wheelNeedsPassword = false;
  };

  services.openssh = {
    enable = true;
    openFirewall = true;
    settings = {
      AllowUsers = ["maestro"];
      KbdInteractiveAuthentication = false;
      PasswordAuthentication = false;
      AuthorizedKeysFile = "/run/maestro-bootstrap/authorized_keys";
      PermitEmptyPasswords = false;
      PermitRootLogin = "no";
      PubkeyAuthentication = true;
      X11Forwarding = false;
    };
  };

  systemd.packages = [pkgs.xen-guest-agent];
  systemd.services.xen-guest-agent.wantedBy = ["multi-user.target"];

  environment.systemPackages = [installMaestro enrollBootstrapKey];

  nix.settings = {
    experimental-features = [
      "nix-command"
      "flakes"
    ];
    extra-substituters = [
      "https://install.determinate.systems"
      "https://nixoa.cachix.org"
      "https://xen-orchestra-ce.cachix.org"
    ];
    extra-trusted-public-keys = [
      "cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM="
      "nixoa.cachix.org-1:N+GsSSd2yKgj2hx01fMG6Oe7tLfbxEi/V0oZFEB721g="
      "xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E="
    ];
  };

  system.stateVersion = "26.05";
}
