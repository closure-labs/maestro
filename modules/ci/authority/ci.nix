{...}: {
  maestro.ci.targets = builtins.fromJSON ''
    {"checks-x86_64-linux-automation-fixtures":{"owner":"ci/authority","attribute":"checks.x86_64-linux.automation-fixtures","name":"automation-fixtures","phases":["validation"],"order":{"validation":8},"dependencies":[],"requirements":["deterministic"]}}
  '';
}
