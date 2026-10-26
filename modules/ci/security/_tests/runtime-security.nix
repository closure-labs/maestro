{
  pkgs,
  inputs,
  appliance,
}: let
  xoPackage = appliance.maestro.xo.package;
in
  pkgs.testers.runNixOSTest {
    name = "maestro-runtime-security";
    nodes = {
      maestro = {
        config,
        lib,
        ...
      }: {
        _module.args.inputs = inputs;
        imports =
          map (path: (import path {}).den.aspects.xo.nixos) [
            ../../../features/xo/options.nix
            ../../../features/xo/service.nix
            ../../../features/xo/storage.nix
            ../../../features/xo/tls.nix
            ../../../features/xo/file-restore.nix
          ]
          ++ [(import ../../../features/operator/access.nix {}).den.aspects.operator.nixos];
        maestro.operator.managementCIDRs = appliance.maestro.operator.managementCIDRs;
        specialisation.hardened.configuration.maestro.operator.managementCIDRs = lib.mkForce ["192.168.0.0/16" "fd42:99::2/128"];
        maestro.xo = {
          enable = true;
          package = xoPackage;
          tls.enable = true;
          tls.autoCert = true;
          storage = {
            enableNFS = true;
            enableCIFS = true;
            enableVHD = true;
          };
        };
        services.openssh = {
          enable = true;
          openFirewall = false;
          settings = appliance.services.openssh.settings;
        };
        users.users.maestro = {
          isNormalUser = true;
          extraGroups = ["wheel"];
        };
        networking.firewall.allowedTCPPorts = appliance.networking.firewall.allowedTCPPorts;
        networking.firewall.allowedUDPPorts = appliance.networking.firewall.allowedUDPPorts;
        virtualisation.memorySize = 1536;
        environment.systemPackages = [pkgs.procps pkgs.iproute2 pkgs.curl];
        environment.etc."maestro-mount-guard.py".source = ../../../features/xo/_source/mount-guard.py;
        environment.etc."maestro-mount-race.py".source = ../../../../tests/xo-mount-race.py;
        environment.etc."maestro-sudo-path".text = "${config.maestro.xo.internal.sudoWrapper}/bin/sudo";
      };
      storage = {...}: {
        virtualisation.memorySize = 512;
        environment.systemPackages = [pkgs.netcat-openbsd pkgs.iproute2 pkgs.iputils];
        services.nfs.server.enable = true;
        services.nfs.server.exports = "/srv/fixture *(rw,sync,no_subtree_check,no_root_squash,insecure)";
        services.samba = {
          enable = true;
          openFirewall = true;
          settings = {
            global = {
              "map to guest" = "Bad User";
              "guest account" = "nobody";
            };
            fixture = {
              path = "/srv/fixture";
              "read only" = "no";
              "guest ok" = "yes";
            };
          };
        };
        networking.firewall.allowedTCPPorts = [111 2049];
        networking.firewall.allowedUDPPorts = [111 2049];
        systemd.tmpfiles.rules = ["d /srv/fixture 1777 root root - -"];
      };
    };
    testScript = ''
      import json
      import re

      start_all()
      storage.wait_for_unit("nfs-server.service")
      storage.wait_for_unit("samba-smbd.service")
      maestro.wait_for_unit("redis-xo.service")
      maestro.wait_for_unit("xo-server.service")
      maestro.wait_for_unit("sshd.service")
      maestro.wait_for_open_port(443)
      # XO opens its listener before mounting the web application.
      maestro.wait_until_succeeds("curl -kfsS --max-time 15 https://localhost/ >/dev/null", timeout=240)
      for port in (22, 80, 443):
          storage.succeed(f"nc -4 -z -w 3 maestro {port}")
      maestro.succeed("ip address add 172.18.0.1/24 dev eth1")
      storage.succeed("ip address add 172.18.0.2/24 dev eth1")
      storage.succeed("ping -4 -c 1 -W 2 -I 172.18.0.2 172.18.0.1")
      maestro.succeed("ip -6 address add fd42:99::1/64 dev eth1")
      storage.succeed("ip -6 address add fd42:99::2/64 dev eth1")
      storage.succeed("ip -6 address add fd42:99::3/64 dev eth1")
      # Prove routing before testing default access or restricted clients.
      for source in ("fd42:99::2", "fd42:99::3"):
          storage.wait_until_succeeds(f"ping -6 -c 1 -W 2 -I {source} fd42:99::1")
      # Initial deployment admits IPv4 and IPv6 sources outside the lab range.
      for port in (22, 80, 443):
          storage.succeed(f"nc -4 -z -w 3 -s 172.18.0.2 172.18.0.1 {port}")
          storage.succeed(f"nc -6 -z -w 3 -s fd42:99::3 fd42:99::1 {port}")
      # Activate the documented restrictions, then verify new connections.
      maestro.succeed("/run/current-system/specialisation/hardened/bin/switch-to-configuration test")
      for port in (22, 80, 443):
          storage.succeed(f"nc -4 -z -w 3 maestro {port}")
          storage.fail(f"nc -4 -z -w 2 -s 172.18.0.2 172.18.0.1 {port}")
          storage.succeed(f"nc -6 -z -w 3 -s fd42:99::2 fd42:99::1 {port}")
          storage.fail(f"nc -6 -z -w 2 -s fd42:99::3 fd42:99::1 {port}")
      maestro.succeed("test $(systemctl show xo-server -p User --value) = xo")
      maestro.succeed("test $(stat -c %a /run/redis-xo/redis.sock) = 770")
      maestro.fail("ss -H -lnt | grep -E ':(6379|23|5900|5353) '")
      # Match ExecStart's explicit configuration path, not OpenSSH's compiled
      # package defaults under /nix/store.
      # OpenSSH 10.5 prints canonical keyword casing (PermitRootLogin).
      # Normalize keywords only; account names and policy values stay exact.
      ssh_dump = maestro.succeed("sshd -T -f /etc/ssh/sshd_config")
      ssh_settings = {}
      for line in ssh_dump.splitlines():
          key, _, value = line.partition(" ")
          ssh_settings.setdefault(key.lower(), []).append(value.strip())
      for key, expected in {"permitrootlogin": ["no"], "passwordauthentication": ["no"], "allowusers": ["maestro"]}.items():
          assert ssh_settings.get(key) == expected, ssh_dump
      maestro.succeed("test $(stat -c %u /var/lib/xo) = 0; test $(stat -c %u /var/lib/xo/mounts) = 0")
      maestro.succeed("systemctl restart xo-server.service")
      maestro.wait_for_unit("xo-server.service")
      maestro.wait_for_open_port(443)
      maestro.succeed("test $(stat -c %u /var/lib/xo) = 0; test $(stat -c %u /var/lib/xo/mounts) = 0")
      xo_pid = maestro.succeed("systemctl show xo-server -p MainPID --value").strip()
      node = maestro.succeed("readlink -f /proc/" + xo_pid + "/exe").strip()
      assert node.startswith("/nix/store/") and node.endswith("/bin/node"), node
      versions = json.loads(maestro.succeed(node + " -p 'JSON.stringify(process.versions)'"))
      openssl_version = versions["openssl"]
      match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", openssl_version)
      assert match is not None, versions
      series = (int(match[1]), int(match[2]))
      # September 2026 fixes have distinct release numbers in each series.
      minimum_patch = {(3, 5): 9, (3, 6): 5}
      assert series in minimum_patch and int(match[3]) >= minimum_patch[series], versions
      maps = maestro.succeed("cat /proc/" + xo_pid + "/maps")
      for library in ("crypto", "ssl"):
          assert "-openssl-" + openssl_version + "/lib/lib" + library + ".so." in maps, maps

      sudo = maestro.succeed("cat /etc/maestro-sudo-path").strip()
      invoke = "runuser -u xo -- " + sudo
      maestro.succeed("runuser -u xo -- mkdir /var/lib/xo/mounts/nfs /var/lib/xo/mounts/cifs /var/lib/xo/mounts/vhd")
      maestro.succeed(invoke + " mount -t nfs -o vers=4 storage:/srv/fixture /var/lib/xo/mounts/nfs")
      maestro.succeed("runuser -u xo -- sh -c 'echo restored-data > /var/lib/xo/mounts/nfs/roundtrip'")
      storage.succeed("grep -Fx restored-data /srv/fixture/roundtrip")
      maestro.succeed(invoke + " umount /var/lib/xo/mounts/nfs")
      maestro.succeed("test $(stat -c %a /var/lib/xo/mounts/nfs) = 770; test $(stat -c %a /var/lib/xo/mounts) = 1770")
      # Run a fresh target through the service's actual capability ceiling;
      # an unrestricted root test would miss missing helper capabilities.
      maestro.succeed("runuser -u xo -- mkdir /var/lib/xo/mounts/service-context")
      ceiling = maestro.succeed("systemctl show xo-server -p CapabilityBoundingSet --value").strip()
      maestro.succeed("systemd-run --wait --pipe --collect --uid=xo --gid=xo --property='CapabilityBoundingSet=" + ceiling + "' " + sudo + " mount -t nfs -o vers=4 storage:/srv/fixture /var/lib/xo/mounts/service-context")
      maestro.succeed(invoke + " umount /var/lib/xo/mounts/service-context")
      maestro.succeed("${pkgs.python3}/bin/python /etc/maestro-mount-race.py " + sudo)
      maestro.succeed("runuser -u xo -- env USER=guest PASSWD=fixture " + sudo + " mount -t cifs -o guest //storage/fixture /var/lib/xo/mounts/cifs")
      maestro.succeed("runuser -u xo -- cat /var/lib/xo/mounts/cifs/roundtrip | grep -Fx restored-data")
      maestro.succeed(invoke + " umount /var/lib/xo/mounts/cifs")
      maestro.succeed("test -z \"$(find /run/maestro-xo-cifs-credentials -type f -print)\"")

      maestro.succeed("truncate -s 8M /var/lib/xo/data/disk.raw; printf VHD-fixture | dd of=/var/lib/xo/data/disk.raw conv=notrunc")
      maestro.succeed("${pkgs.qemu-utils}/bin/qemu-img convert -f raw -O vpc -o subformat=fixed /var/lib/xo/data/disk.raw /var/lib/xo/data/disk.vhd")
      maestro.succeed("chown xo:xo /var/lib/xo/data/disk.vhd")
      maestro.succeed(invoke + " vhdiinfo /var/lib/xo/data/disk.vhd")
      maestro.succeed(invoke + " vhdimount /var/lib/xo/data/disk.vhd /var/lib/xo/mounts/vhd")
      maestro.succeed("head -c 11 /var/lib/xo/mounts/vhd/vhdi1 | grep -Fx VHD-fixture")
      maestro.succeed("runuser -u xo -- head -c 11 /var/lib/xo/mounts/vhd/vhdi1 | grep -Fx VHD-fixture")
      maestro.fail("runuser -u maestro -- head -c 11 /var/lib/xo/mounts/vhd/vhdi1")
      maestro.succeed("test $(ps -o uid= -C vhdimount | xargs) = $(id -u xo)")
      maestro.succeed(invoke + " umount /var/lib/xo/mounts/vhd")

      # Claimed directory names stay protected even when a helper canonicalizes
      # them after validation. XO retains write access to storage contents.
      maestro.fail("runuser -u xo -- mv /var/lib/xo/mounts/nfs /var/lib/xo/mounts/replaced")
      maestro.fail("runuser -u xo -- mv /var/lib/xo/mounts /var/lib/xo/old-mounts")
      maestro.succeed("runuser -u xo -- ln -s /etc /var/lib/xo/mounts/escape")
      maestro.fail(invoke + " mount -t nfs storage:/srv/fixture /var/lib/xo/mounts/escape")
      maestro.fail(invoke + " mount -t nfs storage:/srv/fixture /etc")
      maestro.fail(invoke + " mount --bind -t nfs storage:/srv/fixture /var/lib/xo/mounts/nfs")
      maestro.fail(invoke + " mount -t nfs -o suid,dev storage:/srv/fixture /var/lib/xo/mounts/nfs")
    '';
  }
