{
  pkgs,
  planRunner,
  packerXenserver,
  ciNix,
  appliance,
  lockFile,
  packageSourceRoots,
  applicabilityCommand,
  distributionRoots,
  installerQualification,
  devenv,
  commands,
  common,
}: let
  inherit (common) mkCommand commonInputs spdxSchema boundedGh publicCacheWorker validatePlan classifyPaths;
in {
  security-inventory-preflight = mkCommand {
    name = "security-inventory-preflight";
    prefix = ''
      MAESTRO_SECURITY_INVENTORY_SOURCE=${../_source/security-inventory.py}
      export MAESTRO_SECURITY_INVENTORY_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3];
    source = ../_source/security-inventory-preflight.sh;
  };
  security-inventory = mkCommand {
    name = "security-inventory";
    prefix = let
      context = pkgs.writeText "maestro-security-context.json" (builtins.toJSON {
        schemaVersion = 2;
        platform = pkgs.stdenv.hostPlatform.system;
        # Exact metadata identity, not an implicit build dependency. Native
        # task loading must not build the appliance before cache preflight;
        # the qualification plan materializes these outputs explicitly.
        system = builtins.unsafeDiscardStringContext appliance.system.build.toplevel.outPath;
        distributionRoots = map builtins.unsafeDiscardStringContext distributionRoots;
        installerQualification = builtins.fromJSON (builtins.unsafeDiscardStringContext (builtins.toJSON installerQualification));
        lockDigest = builtins.hashFile "sha256" lockFile;
        inherit packageSourceRoots;
        inventoryDigest = builtins.hashFile "sha256" ../_source/security-inventory.py;
        normalizerDigest = builtins.hashFile "sha256" ../../security/_source/security-normalize.py;
        runtime = {
          inherit (appliance.networking.firewall) allowedTCPPorts allowedUDPPorts;
          managementCIDRs = appliance.maestro.operator.managementCIDRs;
          ssh = appliance.services.openssh.settings;
          xoPackage = builtins.unsafeDiscardStringContext appliance.maestro.xo.package.outPath;
          xoChannel = appliance.maestro.xo.channel;
          xoUser = appliance.maestro.xo.user;
          fileRestore = {
            inherit (appliance.maestro.xo.fileRestore) enable;
            helper = builtins.unsafeDiscardStringContext appliance.systemd.services.xo-server.environment.XO_FILE_RESTORE_HELPER;
          };
          storage = {
            inherit (appliance.maestro.xo.storage) enableNFS enableCIFS enableVHD mountsDir;
          };
          inherit (appliance.systemd.services.xo-server.serviceConfig) CapabilityBoundingSet AmbientCapabilities User Group;
          sudo = appliance.security.sudo.extraRules;
          valkey = appliance.services.redis.servers.xo.settings;
        };
      });
    in ''
      export MAESTRO_FINGERPRINTS_CORE=${../../authority/_source/decisions}
      MAESTRO_SECURITY_INVENTORY_SOURCE=${../_source/security-inventory.py}
      MAESTRO_SECURITY_CONTEXT=${context}
      export MAESTRO_SECURITY_INVENTORY_SOURCE MAESTRO_SECURITY_CONTEXT
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3];
    source = ../_source/security-inventory.sh;
  };
  security-applicability = mkCommand {
    name = "security-applicability";
    prefix = ''
      MAESTRO_SECURITY_APPLICABILITY_RULES=${../_source/security-applicability.json}
      export MAESTRO_SECURITY_APPLICABILITY_RULES
    '';
    runtimeInputs = commonInputs ++ [applicabilityCommand];
    source = ../_source/security-applicability.sh;
  };
}
