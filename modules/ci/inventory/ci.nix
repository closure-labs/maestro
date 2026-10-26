{...}: {
  maestro.ci.targets = builtins.fromJSON ''
    {"packages-x86_64-linux-sbomnix":{"owner":"ci/inventory","attribute":"packages.x86_64-linux.sbomnix","name":"sbomnix","phases":["evidence","publish"],"order":{"evidence":1,"publish":1},"dependencies":[],"requirements":["deterministic"]},"checks-x86_64-linux-sbomnix-runtime":{"owner":"ci/inventory","attribute":"checks.x86_64-linux.sbomnix-runtime","name":"sbomnix-runtime","phases":["evidence"],"order":{"evidence":2},"dependencies":[],"requirements":["deterministic"]}}
  '';
}
