{...}: {
  den.aspects.platform.nixos = {
    key = "modules/features/platform/networking/nixos";
    imports = [
      ({
        inputs,
        lib,
        pkgs,
        ...
      }: {
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
      })
    ];
  };
}
