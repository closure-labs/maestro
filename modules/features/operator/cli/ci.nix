{...}: {
  maestro.ci.targets = {
    checks-x86_64-linux-maestroctl = {
      owner = "features/operator/cli";
      attribute = "checks.x86_64-linux.maestroctl";
      name = "maestroctl";
      phases = ["validation"];
      order = {
        validation = 2;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    packages-x86_64-linux-maestroctl = {
      owner = "features/operator/cli";
      attribute = "packages.x86_64-linux.maestroctl";
      name = "maestroctl";
      phases = ["publish"];
      order = {
        publish = 6;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
  };
}
