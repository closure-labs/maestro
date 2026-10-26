{...}: {
  maestro.ci.targets = builtins.fromJSON ''
    {"packages-x86_64-linux-xen-orchestra-ce":{"owner":"features/xo","attribute":"packages.x86_64-linux.xen-orchestra-ce","name":"xen-orchestra-ce","phases":["evidence"],"order":{"evidence":3},"dependencies":[],"requirements":["deterministic"]},"packages-x86_64-linux-xen-orchestra-supply-protector":{"owner":"features/xo","attribute":"packages.x86_64-linux.xen-orchestra-supply-protector","name":"xen-orchestra-supply-protector","phases":["evidence"],"order":{"evidence":4},"dependencies":[],"requirements":["deterministic","producer-binding"]}}
  '';
}
