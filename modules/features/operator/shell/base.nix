{...}: {
  den.aspects.operator.homeManager =
    # SPDX-License-Identifier: Apache-2.0
    # Home Manager base settings
    {osConfig, ...}: let
      cfg = osConfig.maestro.operator;
    in {
      home = {
        stateVersion = osConfig.system.stateVersion;
        username = cfg.username;
        homeDirectory = "/home/${cfg.username}";
      };

      programs.home-manager.enable = true;
    };
}
