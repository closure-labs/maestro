{...}: {
  den.aspects.xcp-ng.nixos =
    # SPDX-License-Identifier: Apache-2.0
    {pkgs, ...}: {
      # Maestro is always an XCP-ng guest. Disk and filesystem declarations are
      # intentionally left entirely to host/hardware-configuration.nix.
      systemd.packages = [pkgs.xen-guest-agent];
      systemd.services.xen-guest-agent.wantedBy = ["multi-user.target"];
      environment.systemPackages = [pkgs.cloud-init];

      # Xen Orchestra supplies a NoCloud config drive when one is requested for a
      # clone. Cloud-init is intentionally limited to instance identity and SSH
      # key provisioning: NixOS remains authoritative for users, networking,
      # filesystems, packages, and services.
      services.cloud-init = {
        enable = true;
        network.enable = false;
        settings = {
          datasource_list = [
            "NoCloud"
            "None"
          ];
          preserve_hostname = true;
          manage_etc_hosts = false;
          network.config = "disabled";
          disable_network_activation = true;
          disable_root = true;
          ssh_pwauth = false;
          ssh_deletekeys = false;
          growpart = {
            mode = "auto";
            devices = ["/"];
            ignore_growroot_disabled = false;
          };
          resize_rootfs = true;
          # NixOS owns SSH host-key generation. Running cloud-init's key generator
          # concurrently races sshd-keygen.service on the first clone boot.
          ssh_genkeytypes = [];
          ssh.emit_keys_to_console = false;
          users = ["default"];
          system_info.default_user = {
            name = "maestro";
            gecos = "Maestro operator";
            homedir = "/home/maestro";
            groups = [
              "users"
              "wheel"
              "systemd-journal"
            ];
            sudo = null;
            shell = "/run/current-system/sw/bin/bash";
            lock_passwd = true;
          };

          # Cloud-init may grow only the existing root partition and filesystem.
          # NixOS still owns networking, packages, and executable configuration.
          cloud_init_modules = [
            "seed_random"
            "growpart"
            "resizefs"
          ];
          cloud_config_modules = ["ssh"];
          cloud_final_modules = [
            "ssh-authkey-fingerprints"
            "keys-to-console"
            "final-message"
          ];
        };
      };

      # Do not expose SSH until NoCloud keys have been applied.
      systemd.services.sshd = {
        wants = ["cloud-config.service"];
        after = ["cloud-config.service"];
      };

      # Older clones may retain fallback networkd files rendered by
      # cloud-init-local before network configuration was disabled explicitly.
      system.activationScripts.removeCloudInitNetwork = {
        deps = ["etc"];
        text = ''
          ${pkgs.coreutils}/bin/rm -f /etc/systemd/network/10-cloud-init-*.network
        '';
      };
    };
}
