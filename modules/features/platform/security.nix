{...}: {
  den.aspects.platform.nixos = {
    key = "modules/features/platform/security/nixos";
    imports = [
      ({
        inputs,
        lib,
        pkgs,
        ...
      }: {
        security.polkit = {
          enable = true;
          extraConfig = ''
            polkit.addRule(function(action, subject) {
              if (action.id == "org.freedesktop.hostname1.set-hostname" &&
                  subject.user == "systemd-network") {
                return polkit.Result.YES;
              }
            });
          '';
        };
      })
    ];
  };
}
