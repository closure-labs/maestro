{...}: {
  maestro.ci.targets = {
    checks-x86_64-linux-operator-fixtures = {
      owner = "features/operator";
      attribute = "checks.x86_64-linux.operator-fixtures";
      name = "operator-fixtures";
      phases = ["validation"];
      order = {
        validation = 12;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
  };
}
