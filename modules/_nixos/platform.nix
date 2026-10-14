# SPDX-License-Identifier: Apache-2.0
{
  inputs,
  lib,
  pkgs,
  ...
}: let
  # Retain the official output for cache preflight/provenance; the installed
  # runtime below is rebuilt from the same source with appliance dependencies.
  upstreamDeterminateNix = inputs.determinate.inputs.nix.packages.${pkgs.stdenv.hostPlatform.system}.default;
  # Use the upstream public source-build interface with patched appliance
  # dependencies. This rebuilds the actual linked runtime, including Nix's
  # libarchive/OpenSSL consumers; changing a CLI package would not do that.
  determinateComponents = inputs.determinate.inputs.nix.lib.makeComponents {inherit pkgs;};
  patchedDeterminateNix = determinateComponents.nix-everything;
  determinateNix = pkgs.symlinkJoin {
    name = "determinate-nix-${upstreamDeterminateNix.version}";
    paths = [patchedDeterminateNix.out];
    passthru = {
      upstream = upstreamDeterminateNix;
      patched = patchedDeterminateNix;
      inherit (upstreamDeterminateNix) pname version;
    };
    meta =
      (upstreamDeterminateNix.meta or {})
      // {
        outputsToInstall = ["out"];
      };
  };
in {
  imports = [inputs.determinate.nixosModules.default];

  networking = {
    useDHCP = lib.mkDefault false;
    useNetworkd = true;
    networkmanager.enable = false;
    dhcpcd.enable = false;
    firewall = {
      enable = true;
      allowPing = true;
      logRefusedConnections = false;
    };
  };

  systemd.network = {
    enable = true;
    wait-online.anyInterface = true;
    networks."10-uplink" = {
      matchConfig.Type = "ether";
      networkConfig = {
        DHCP = "yes";
        IPv6AcceptRA = true;
      };
      linkConfig.RequiredForOnline = "routable";
    };
  };

  # networkd applies DHCP-provided transient hostnames through hostnamed.
  # Authorize only that action for networkd's dedicated service account.
  security.polkit = {
    enable = true;
    extraConfig = ''
      polkit.addRule(function(action, subject) {
        if (action.id == "org.freedesktop.hostname1.set-hostname" &&
            subject.user == "systemd-network") {
          return polkit.Result.YES;
        }
      });
    '';
  };

  i18n.defaultLocale = "en_US.UTF-8";
  i18n.extraLocaleSettings = {
    LC_TIME = "en_US.UTF-8";
    LC_NUMERIC = "en_US.UTF-8";
    LC_MONETARY = "en_US.UTF-8";
    LC_PAPER = "en_US.UTF-8";
    LC_NAME = "en_US.UTF-8";
    LC_ADDRESS = "en_US.UTF-8";
    LC_TELEPHONE = "en_US.UTF-8";
    LC_MEASUREMENT = "en_US.UTF-8";
    LC_IDENTIFICATION = "en_US.UTF-8";
  };

  boot.loader.systemd-boot.configurationLimit = 10;

  services.journald.extraConfig = ''
    Storage=persistent
    SystemMaxUse=1G
    SystemMaxFileSize=100M
    MaxRetentionSec=30d
    ForwardToConsole=no
    Compress=yes
  '';

  # A system switch must not bounce the system message bus underneath the
  # activation transaction.
  systemd.services = {
    dbus = {
      reloadIfChanged = lib.mkForce false;
      restartIfChanged = lib.mkForce false;
    };
    dbus-broker = {
      reloadIfChanged = lib.mkForce false;
      restartIfChanged = lib.mkForce false;
    };
  };

  environment.systemPackages = with pkgs; [
    inputs.xen-orchestra-ce.inputs.nixpkgs.legacyPackages.${pkgs.stdenv.hostPlatform.system}.vim
    nano
    micro
    wget
    curl
    htop
    btop
    tree
    ncdu
    tmux
    git
    rsync
    lsof
    iotop
    sysstat
    dool
    openssl
    nettools
    nmap
    tcpdump
    dig
    traceroute
  ];

  nix = {
    package = lib.mkForce determinateNix;
    settings = {
      extra-substituters = [
        "https://install.determinate.systems"
        "https://maestro.cachix.org"
        "https://xen-orchestra-ce.cachix.org"
        "https://devenv.cachix.org"
        "https://nix-community.cachix.org"
      ];
      extra-trusted-public-keys = [
        "cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM="
        "maestro.cachix.org-1:fGFZFVwe2ZHEBENWZLHVzERZrz2c50ru+g0UewH68I0="
        "xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E="
        "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw="
        "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
      ];
      trusted-users = [
        "root"
        "@wheel"
      ];
    };
    gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 30d";
    };
  };
}
