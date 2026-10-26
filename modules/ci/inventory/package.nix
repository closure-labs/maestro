{inputs, ...}: {
  perSystem = {
    pkgs,
    system,
    ciNix,
    lib,
    installerQualification,
    ...
  }: {
    packages = {
      sbomnix = import ../../../nix/pkgs/sbomnix.nix {inherit pkgs ciNix;};
      distribution-inventory = (pkgs.linkFarm "maestro-distribution-inventory" (
        map (target: {
          inherit (target) name;
          path = lib.attrByPath (lib.splitString "." target.attribute) null inputs.self;
        })
        inputs.self.lib.ciPlans.${system}.publish.targets
        ++ lib.mapAttrsToList (name: path: {inherit name path;}) installerQualification.roots
      )).overrideAttrs (_: {passthru.qualification = installerQualification;});
    };
  };
}
