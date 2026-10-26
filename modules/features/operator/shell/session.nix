{...}: {
  den.aspects.operator.homeManager = {
    key = "modules/features/operator/shell/session/homeManager";
    imports = [
      (
        # SPDX-License-Identifier: Apache-2.0
        # Home session variables
        {osConfig, ...}: let
          operator = osConfig.maestro.operator;
        in {
          home.sessionVariables = {
            MAESTRO_SYSTEM_ROOT = operator.repoDir;
            XO_MOUNTS = osConfig.maestro.xo.storage.mountsDir;
          };
        }
      )
    ];
  };
}
