{...}: {
  den.aspects.platform.nixos = {
    inputs,
    lib,
    pkgs,
    ...
  }: {
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
  };
}
