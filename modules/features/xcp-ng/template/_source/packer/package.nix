# SPDX-License-Identifier: Apache-2.0
{
  lib,
  packer,
  packerXenserverPlugin,
  stdenv,
  writeShellApplication,
}: let
  pluginVersion = packerXenserverPlugin.version;
  pluginPath = "github.com/vatesfr/xenserver";
  pluginName = "packer-plugin-xenserver_v${pluginVersion}_x5.0_${stdenv.hostPlatform.go.GOOS}_${stdenv.hostPlatform.go.GOARCH}";
  pluginTree = stdenv.mkDerivation {
    pname = "packer-xenserver-plugin-tree";
    version = pluginVersion;
    dontUnpack = true;
    installPhase = ''
      destination="$out/${pluginPath}"
      mkdir -p "$destination"
      ln -s \
        "${lib.getExe packerXenserverPlugin}" \
        "$destination/${pluginName}"
      sha256sum "${lib.getExe packerXenserverPlugin}" \
        | cut -d ' ' -f 1 \
        > "$destination/${pluginName}_SHA256SUM"
    '';
  };
in
  writeShellApplication {
    name = "packer-xenserver";
    runtimeInputs = [packer];
    text = ''
      export PACKER_PLUGIN_PATH=${pluginTree}
      exec packer "$@"
    '';
    meta = {
      description = "Packer wrapped with the pinned Vates XenServer plugin";
      inherit (packerXenserverPlugin.meta) homepage license platforms;
    };
  }
