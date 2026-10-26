{...}: {
  den.aspects.operator.nixos =
    # SPDX-License-Identifier: Apache-2.0
    {
      config,
      lib,
      ...
    }: let
      cidrs = config.maestro.operator.managementCIDRs;
      octet = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
      ipv4Pattern = "${octet}(\\.${octet}){3}/(3[0-2]|[12]?[0-9])";
      # Parse the address separately: Nixpkgs rejects a /0 prefix in its parser.
      cidrType = lib.types.addCheck lib.types.str (cidr: let
        ipv6 = builtins.match "([0-9A-Fa-f:]+)/(12[0-8]|1[01][0-9]|[1-9]?[0-9])" cidr;
      in
        builtins.match ipv4Pattern cidr
        != null
        || (ipv6
          != null
          && (builtins.tryEval (builtins.deepSeq (lib.network.ipv6.fromString (builtins.head ipv6)) true)).success));
      isIPv6 = cidr: lib.hasInfix ":" cidr;
      ports = [22 80 443];
    in {
      options.maestro.operator.managementCIDRs = lib.mkOption {
        type = lib.types.listOf cidrType;
        default = ["0.0.0.0/0" "::/0"];
        example = ["192.168.0.0/16" "fd42:99::/64"];
        description = "IPv4 and IPv6 client CIDRs allowed to reach SSH and the XO HTTP/HTTPS management UI. Defaults to all clients for initial deployment; restrict these ranges after deployment as described in docs/hardening.md. Omit a family to close its management ingress.";
      };
      config = {
        networking.firewall.extraCommands =
          lib.mkIf (!config.networking.nftables.enable)
          (lib.concatMapStringsSep "\n" (cidr: "${
              if isIPv6 cidr
              then "ip6tables"
              else "iptables"
            } -A nixos-fw -s ${lib.escapeShellArg cidr} -p tcp -m multiport --dports 22,80,443 -j nixos-fw-accept")
            cidrs);
        networking.firewall.extraInputRules =
          lib.mkIf config.networking.nftables.enable
          (lib.concatMapStringsSep "\n" (cidr: "${
              if isIPv6 cidr
              then "ip6"
              else "ip"
            } saddr ${cidr} tcp dport { 22, 80, 443 } accept")
            cidrs);
        assertions = [
          {
            assertion = cidrs != [];
            message = "maestro.operator.managementCIDRs must declare at least one allowed client range.";
          }
          {
            assertion =
              !(lib.any (port: builtins.elem port ports) config.networking.firewall.allowedTCPPorts
                || lib.any (range: lib.any (port: port >= range.from && port <= range.to) ports) config.networking.firewall.allowedTCPPortRanges);
            message = "SSH and XO management ports must use managementCIDRs rather than globally allowed TCP ports.";
          }
        ];
      };
    };
}
