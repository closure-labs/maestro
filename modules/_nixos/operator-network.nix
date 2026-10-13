# SPDX-License-Identifier: Apache-2.0
{
  config,
  lib,
  ...
}: let
  cidrs = config.maestro.operator.managementCIDRs;
  octet = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
  cidrType = lib.types.strMatching "${octet}(\\.${octet}){3}/(3[0-2]|[12]?[0-9])";
  ports = [22 80 443];
in {
  options.maestro.operator.managementCIDRs = lib.mkOption {
    type = lib.types.listOf cidrType;
    default = [];
    example = ["192.168.0.0/16"];
    description = "IPv4 client CIDRs allowed to reach SSH and the XO HTTP/HTTPS management UI. IPv6 management ingress remains closed.";
  };
  config = {
    networking.firewall.extraCommands =
      lib.mkIf (!config.networking.nftables.enable)
      (lib.concatMapStringsSep "\n" (cidr: "iptables -A nixos-fw -s ${lib.escapeShellArg cidr} -p tcp -m multiport --dports 22,80,443 -j nixos-fw-accept") cidrs);
    networking.firewall.extraInputRules =
      lib.mkIf config.networking.nftables.enable
      (lib.concatMapStringsSep "\n" (cidr: "ip saddr ${cidr} tcp dport { 22, 80, 443 } accept") cidrs);
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
}
