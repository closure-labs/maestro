{
  inputs,
  lib,
  ...
}: {
  perSystem = {
    pkgs,
    system,
    ...
  }: let
    packages = inputs.self.packages.${system};
    appliance = inputs.self.nixosConfigurations.maestro.config;
    xoPackages = inputs.xen-orchestra-ce.packages.${system};
    managementCIDRType = inputs.self.nixosConfigurations.maestro.options.maestro.operator.managementCIDRs.type.nestedTypes.elemType;
    xoConfigFeatures = ["http" "redis" "remotes" "web"];
    xoConfigFragments = appliance.maestro.xo.internal.configFragments;
  in {
    checks = {
      configuration = assert inputs.self.lib.ciQualificationInputs.${system}.media.dependencies.applianceToplevel == appliance.system.build.toplevel.outPath;
      assert appliance.maestro.xo.enable;
      assert appliance.maestro.xo.channel == "latest";
      assert lib.all (channel: builtins.hasAttr channel xoPackages) ["latest" "stable" "rolling"];
      assert appliance.maestro.xo.package == xoPackages.latest;
      assert builtins.attrNames xoConfigFragments == xoConfigFeatures;
      assert lib.all (
        feature: builtins.hasAttr "xo-server/config.nixos-${feature}.toml" appliance.environment.etc
      )
      xoConfigFeatures;
      assert xoConfigFragments.redis.redis.socket == "/run/redis-xo/redis.sock";
      assert xoConfigFragments.remotes.remoteOptions.mountsDir == appliance.maestro.xo.storage.mountsDir;
      assert xoConfigFragments.remotes.remoteOptions.useSudo;
      assert xoConfigFragments.http.http.redirectToHttps == appliance.maestro.xo.tls.enable;
      assert builtins.length xoConfigFragments.http.http.listen == 2;
      assert xoConfigFragments.web.http.mounts."/v6" == "${appliance.maestro.xo.home}/xen-orchestra/@xen-orchestra/web/dist";
      assert appliance.systemd.services.xo-server.environment.TMPDIR == appliance.maestro.xo.tempDir;
      assert appliance.maestro.xo.fileRestore.enable;
      assert appliance.systemd.services.xo-server.environment.XO_FILE_RESTORE_HELPER == lib.getExe appliance.maestro.xo.internal.fileRestorePackage;
      assert appliance.maestro.xo.storage.libvhdiPackage == inputs.xen-orchestra-ce.packages.x86_64-linux.libvhdi;
      assert appliance.programs.fuse.userAllowOther;
      assert builtins.elem "fuse" appliance.users.users.${appliance.maestro.xo.user}.extraGroups;
      assert appliance.services.redis.servers.xo.enable;
      assert appliance.systemd.services ? xo-autocert;
      assert appliance.maestro.xo.internal.sudoWrapper != null;
      assert builtins.elem "multi-user.target" appliance.systemd.services.xen-guest-agent.wantedBy;
      assert appliance.services.cloud-init.enable;
      assert !appliance.services.cloud-init.network.enable;
      assert appliance.services.cloud-init.settings.datasource_list == ["NoCloud" "None"];
      assert appliance.services.cloud-init.settings.system_info.default_user.name == "maestro";
      assert appliance.services.cloud-init.settings.cloud_init_modules
      == [
        "seed_random"
        "growpart"
        "resizefs"
      ];
      assert appliance.services.cloud-init.settings.growpart.devices == ["/"];
      assert appliance.services.cloud-init.settings.resize_rootfs;
      assert appliance.services.cloud-init.settings.network.config == "disabled";
      assert appliance.services.cloud-init.settings.disable_network_activation;
      assert appliance.services.cloud-init.settings.ssh_genkeytypes == [];
      assert !appliance.services.cloud-init.settings.ssh.emit_keys_to_console;
      assert appliance.security.polkit.enable;
      assert builtins.elem pkgs.cloud-init appliance.environment.systemPackages;
      assert builtins.elem "cloud-config.service" appliance.systemd.services.sshd.after;
      assert appliance.services.openssh.settings.AllowUsers == ["maestro"];
      assert appliance.services.openssh.settings.PermitRootLogin == "no";
      assert !appliance.services.openssh.settings.PasswordAuthentication;
      assert !appliance.services.openssh.settings.KbdInteractiveAuthentication;
      assert appliance.users.users.xo.isSystemUser;
      assert appliance.users.users.xo.shell == "${pkgs.shadow}/bin/nologin";
      assert appliance.services.redis.servers.xo.settings.port == 0;
      assert appliance.services.redis.servers.xo.unixSocketPerm == 770;
      assert appliance.systemd.services.xo-server.serviceConfig.User == "xo";
      assert appliance.systemd.services.xo-server.serviceConfig.ProtectHome;
      assert appliance.systemd.services.xo-server.serviceConfig.ProtectSystem == "full";
      assert appliance.systemd.services.xo-server.serviceConfig.AmbientCapabilities == ["CAP_NET_BIND_SERVICE"];
      assert appliance.systemd.services.xo-server.serviceConfig.EnvironmentFile == [];
      assert lib.all (rule: !(builtins.elem "xo" rule.users) || lib.all (command: lib.hasSuffix "/bin/xo-storage-helper" command.command) rule.commands) appliance.security.sudo.extraRules;
      assert appliance.networking.firewall.allowedTCPPorts == [];
      assert appliance.maestro.operator.managementCIDRs == ["0.0.0.0/0" "::/0"];
      assert lib.all managementCIDRType.check ["0.0.0.0/0" "::/0" "192.168.98.0/24" "2001:db8::1/128"];
      assert lib.all (cidr: !managementCIDRType.check cidr) ["0.0.0.0" "256.0.0.0/8" "192.168.0.0/33" "::/129" "2001:::1/64" "12345::/64" "::/0;accept"];
      assert !appliance.services.openssh.openFirewall;
      assert appliance.networking.firewall.allowedUDPPorts == [];
      assert !appliance.services.avahi.enable;
      assert !appliance.services.samba.enable;
      assert !appliance.hardware.bluetooth.enable;
      assert !appliance.virtualisation.libvirtd.enable;
      assert !appliance.services.nfs.server.enable;
      assert appliance.determinate.enable;
      assert appliance.home-manager.users.maestro.programs.git.enable;
      assert appliance.nix.gc.automatic;
      assert appliance.boot.loader.systemd-boot.configurationLimit == 10;
        pkgs.runCommandLocal "maestro-configuration-assertions" {} ''
          touch "$out"
        '';
    };
  };
}
