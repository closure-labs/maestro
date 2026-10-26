{...}: {
  maestro.ci.targets = {
    packages-x86_64-linux-installer-iso = {
      owner = "features/installer";
      attribute = "packages.x86_64-linux.installer-iso";
      name = "installer-iso";
      phases = ["media"];
      order = {
        media = 0;
      };
      dependencies = ["nixosConfigurations-maestro-config-system-build-toplevel" "packages-x86_64-linux-maestro-menu" "packages-x86_64-linux-xen-orchestra-ce"];
      requirements = ["deterministic" "verified-boot"];
      link = "result-installer";
    };
  };
}
