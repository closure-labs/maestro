{...}: {
  maestro.ci.targets = {
    packages-x86_64-linux-maestro-menu = {
      owner = "features/operator/menu";
      attribute = "packages.x86_64-linux.maestro-menu";
      name = "maestro-menu";
      phases = ["publish"];
      order = {
        publish = 5;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
  };
}
