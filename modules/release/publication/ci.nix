{...}: {
  maestro.ci.targets = {
    checks-x86_64-linux-release-fixtures = {
      owner = "release/publication";
      attribute = "checks.x86_64-linux.release-fixtures";
      name = "release-fixtures";
      phases = ["validation"];
      order = {
        validation = 10;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
  };
}
