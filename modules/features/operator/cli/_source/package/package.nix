{
  lib,
  bash,
  coreutils,
  findutils,
  gawk,
  git,
  glibc,
  gnugrep,
  gnused,
  nettools,
  iproute2,
  jq,
  nix,
  nixos-rebuild,
  nh,
  systemd,
  util-linux,
  writeShellApplication,
  repoRootDefault ? null,
}:
writeShellApplication {
  name = "maestroctl";
  runtimeInputs = [
    bash
    coreutils
    findutils
    gawk
    git
    glibc.bin
    gnugrep
    gnused
    nettools
    iproute2
    jq
    nix
    nixos-rebuild
    nh
    systemd
    util-linux
  ];
  checkPhase = ":";
  text = ''
    ${lib.optionalString (repoRootDefault != null) ''
      if [ -z "''${MAESTRO_SYSTEM_ROOT:-}" ]; then
        export MAESTRO_SYSTEM_ROOT=${lib.escapeShellArg repoRootDefault}
      fi
    ''}

    ${builtins.readFile ../maestroctl.sh}
  '';

  meta = {
    description = "Canonical Maestro operator CLI";
    homepage = "https://github.com/closure-labs/maestro";
    license = lib.licenses.asl20;
    mainProgram = "maestroctl";
    platforms = lib.platforms.linux;
  };
}
