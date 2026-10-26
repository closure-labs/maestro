{inputs, ...}: {
  perSystem = {system, ...}: {
    packages = {
      xen-orchestra-ce = inputs.xen-orchestra-ce.packages.${system}.latest;
      xen-orchestra-supply-protector = inputs.xen-orchestra-ce.packages.${system}.supply-protector-latest;
      libvhdi = inputs.xen-orchestra-ce.packages.${system}.libvhdi;
      default = inputs.xen-orchestra-ce.packages.${system}.latest;
    };
  };
}
