{...}: {
  maestro.ci.targets = {
    checks-x86_64-linux-devenv-contract = {
      owner = "features/development";
      attribute = "checks.x86_64-linux.devenv-contract";
      name = "devenv-contract";
      phases = ["validation"];
      order = {
        validation = 6;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    checks-x86_64-linux-secretspec-contract = {
      owner = "features/development";
      attribute = "checks.x86_64-linux.secretspec-contract";
      name = "secretspec-contract";
      phases = ["validation"];
      order = {
        validation = 11;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
    packages-x86_64-linux-maestro-ci-toolchain = {
      owner = "features/development";
      attribute = "packages.x86_64-linux.maestro-ci-toolchain";
      name = "maestro-ci-toolchain";
      phases = ["publish"];
      order = {
        publish = 0;
      };
      dependencies = [];
      requirements = ["deterministic"];
    };
  };
}
