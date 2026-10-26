{...}: {
  maestro.ci.targets = {
    checks-x86_64-linux-security-fixtures = {
      owner = "ci/security";
      attribute = "checks.x86_64-linux.security-fixtures";
      name = "security-fixtures";
      phases = ["validation"];
      order = {
        validation = 16;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    checks-x86_64-linux-runtime-security = {
      owner = "ci/security";
      attribute = "checks.x86_64-linux.runtime-security";
      name = "runtime-security";
      phases = ["validation"];
      order = {
        validation = 17;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    checks-x86_64-linux-source-security = {
      owner = "ci/security";
      attribute = "checks.x86_64-linux.source-security";
      name = "source-security";
      phases = ["validation"];
      order = {
        validation = 19;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
  };
}
