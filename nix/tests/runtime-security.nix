{
  pkgs,
  inputs,
  appliance,
}: let
  xoPackage = appliance.maestro.xo.package;
  node = inputs.xen-orchestra-ce.inputs.nixpkgs.legacyPackages.x86_64-linux.nodejs_22;
in
  pkgs.testers.runNixOSTest {
    name = "maestro-runtime-security";
    nodes = {
      maestro = {config, ...}: {
        _module.args.inputs = inputs;
        imports = [../../modules/_nixos/xo];
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
        environment.etc."maestro-mount-guard.py".source = ../../modules/_nixos/xo/mount-guard.py;
        environment.etc."maestro-mount-race.py".source = ../../tests/xo-mount-race.py;
        environment.etc."maestro-sudo-path".text = "${config.maestro.xo.internal.sudoWrapper}/bin/sudo";
      };
      storage = {...}: {
        virtualisation.memorySize = 512;
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

      start_all()
      storage.wait_for_unit("nfs-server.service")
      storage.wait_for_unit("samba-smbd.service")
      maestro.wait_for_unit("redis-xo.service")
      maestro.wait_for_unit("xo-server.service")
      maestro.wait_for_unit("sshd.service")
      maestro.wait_for_open_port(443)
      maestro.succeed("curl -kf --max-time 15 https://localhost/ >/dev/null")
      maestro.succeed("test $(systemctl show xo-server -p User --value) = xo")
      maestro.succeed("test $(stat -c %a /run/redis-xo/redis.sock) = 770")
      maestro.fail("ss -H -lnt | grep -E ':(6379|23|5900|5353) '")
      maestro.succeed("sshd -T | grep -Fx 'permitrootlogin no'")
      maestro.succeed("sshd -T | grep -Fx 'passwordauthentication no'")
      maestro.succeed("sshd -T | grep -Fx 'allowusers maestro'")
      maestro.succeed("test $(stat -c %u /var/lib/xo) = 0; test $(stat -c %u /var/lib/xo/mounts) = 0")
      maestro.succeed("systemctl restart xo-server.service")
      maestro.wait_for_unit("xo-server.service")
      maestro.wait_for_open_port(443)
      maestro.succeed("test $(stat -c %u /var/lib/xo) = 0; test $(stat -c %u /var/lib/xo/mounts) = 0")
      maestro.succeed("${node}/bin/node -p process.versions.openssl | grep '^3\\.6\\.5'")

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
