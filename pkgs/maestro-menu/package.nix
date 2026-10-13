{
  lib,
  bash,
  coreutils,
  gawk,
  git,
  gnugrep,
  gnused,
  nettools,
  iproute2,
  makeWrapper,
  nix,
  rustPlatform,
  repoRootDefault ? null,
}: let
  runtimePath = lib.makeBinPath [
    bash
    coreutils
    gawk
    git
    gnugrep
    gnused
    nettools
    iproute2
    nix
  ];
  wrapperArgs =
    lib.optionals (repoRootDefault != null) [
      "--set-default"
      "MAESTRO_SYSTEM_ROOT"
      repoRootDefault
    ]
    ++ [
      "--prefix"
      "PATH"
      ":"
      runtimePath
    ];
in
  rustPlatform.buildRustPackage {
    pname = "maestro-menu";
    version = "0.7.0";

    src = lib.cleanSource ./.;

    cargoLock = {
      lockFile = ./Cargo.lock;
    };

    nativeBuildInputs = [makeWrapper];

    postInstall = ''
      wrapProgram "$out/bin/maestro-menu" ${lib.escapeShellArgs wrapperArgs}
    '';

    meta = {
      description = "Ratatui-based SSH administration console for the Maestro appliance";
      homepage = "https://github.com/closure-labs/maestro";
      license = lib.licenses.asl20;
      mainProgram = "maestro-menu";
      platforms = lib.platforms.linux;
    };
  }
