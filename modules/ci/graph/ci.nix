{...}: {
  maestro.ci.targets = {
    checks-x86_64-linux-flake-plan-runner = {
      owner = "ci/graph";
      attribute = "checks.x86_64-linux.flake-plan-runner";
      name = "flake-plan-runner";
      phases = ["validation"];
      order = {
        validation = 3;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    checks-x86_64-linux-qualification-input-fixtures = {
      owner = "ci/graph";
      attribute = "checks.x86_64-linux.qualification-input-fixtures";
      name = "qualification-input-fixtures";
      phases = ["validation"];
      order = {
        validation = 9;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    checks-x86_64-linux-ci-plan-contract = {
      owner = "ci/graph";
      attribute = "checks.x86_64-linux.ci-plan-contract";
      name = "ci-plan-contract";
      phases = ["validation"];
      order = {
        validation = 15;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
  };
}
