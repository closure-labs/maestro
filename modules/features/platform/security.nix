{...}: {
  den.aspects.platform.nixos = {
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
  };
}
