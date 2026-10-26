{
  coreutils,
  gawk,
  gh,
  git,
  jq,
  lib,
  nix,
  packerXenserver,
  openssh,
  pass,
  qualificationValidation,
  writeShellApplication,
}: let
  buildTemplate = writeShellApplication {
    name = "maestro-build-template";
    runtimeInputs =
      [
        coreutils
        gawk
        gh
        git
        jq
        nix
        packerXenserver
        openssh
      ]
      ++ qualificationValidation;
    text = builtins.readFile ../build.sh;
    meta = {
      description = "Build a native Maestro XCP-ng template with Packer";
      license = lib.licenses.asl20;
      mainProgram = "maestro-build-template";
      platforms = ["x86_64-linux"];
    };
  };

  deployTemplate = writeShellApplication {
    name = "maestro-deploy-template";
    runtimeInputs = [
      buildTemplate
      coreutils
      git
      jq
      pass
    ];
    text = builtins.readFile ../deploy-template.sh;
    meta = {
      description = "Configure and deploy a native Maestro XCP-ng template";
      license = lib.licenses.asl20;
      mainProgram = "maestro-deploy-template";
      platforms = ["x86_64-linux"];
    };
  };
in {
  build = buildTemplate;
  deploy = deployTemplate;
}
