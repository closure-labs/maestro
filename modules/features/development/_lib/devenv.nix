{pkgs, ...}: {
  imports = [../../../ci/graph/_lib/tasks.nix ../../installer/_lib/tasks.nix ../../appliance/_lib/tasks.nix ../../../ci/inventory/_lib/tasks.nix ./tasks.nix ../../../ci/authority/_lib/tasks.nix ../../../ci/security/_lib/tasks.nix ../../../release/publication/_lib/tasks.nix ../../../ci/checks/_lib/tasks.nix ../../xcp-ng/template/_lib/tasks.nix];

  packages = import ./packages.nix {inherit pkgs;};

  # Public pulls need no credentials. Publication is the explicit audited task
  # below, so ordinary hosted jobs cannot automatically push realized closures.
  cachix.pull = [
    "maestro"
    "xen-orchestra-ce"
    "nix-community"
  ];
}
