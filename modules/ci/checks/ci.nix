{...}: {
  maestro.ci.targets = {
    checks-x86_64-linux-maestro-ci-repository-audit = {
      owner = "ci/checks";
      attribute = "checks.x86_64-linux.maestro-ci-repository-audit";
      name = "maestro-ci-repository-audit";
      phases = ["validation"];
      order = {
        validation = 1;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    checks-x86_64-linux-eval-smoke = {
      owner = "ci/checks";
      attribute = "checks.x86_64-linux.eval-smoke";
      name = "eval-smoke";
      phases = ["validation"];
      order = {
        validation = 4;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    checks-x86_64-linux-workflow-policy = {
      owner = "ci/checks";
      attribute = "checks.x86_64-linux.workflow-policy";
      name = "workflow-policy";
      phases = ["validation"];
      order = {
        validation = 5;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    checks-x86_64-linux-shell-lint = {
      owner = "ci/checks";
      attribute = "checks.x86_64-linux.shell-lint";
      name = "shell-lint";
      phases = ["validation"];
      order = {
        validation = 7;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    checks-x86_64-linux-repository-policy = {
      owner = "ci/checks";
      attribute = "checks.x86_64-linux.repository-policy";
      name = "repository-policy";
      phases = ["validation"];
      order = {
        validation = 13;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
  };
}
