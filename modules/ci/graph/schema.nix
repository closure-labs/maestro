{lib, ...}: {
  options.maestro.ci.gatingEnabled = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Use graph job decisions after hosted full-versus-reuse qualification.";
  };
  options.maestro.ci.targets = lib.mkOption {
    default = {};
    description = "Feature-owned CI targets; evaluated derivations define product identity.";
    type = lib.types.attrsOf (lib.types.submodule {
      options = {
        owner = lib.mkOption {type = lib.types.str;};
        attribute = lib.mkOption {type = lib.types.str;};
        name = lib.mkOption {type = lib.types.str;};
        phases = lib.mkOption {type = lib.types.listOf (lib.types.enum ["validation" "media" "evidence" "publish"]);};
        order = lib.mkOption {type = lib.types.attrsOf lib.types.ints.unsigned;};
        link = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
        };
        dependencies = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
        };
        requirements = lib.mkOption {
          type = lib.types.listOf (lib.types.enum ["deterministic" "verified-boot" "producer-binding"]);
          default = ["deterministic"];
        };
      };
    });
  };
}
