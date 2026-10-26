{
  coreutils,
  findutils,
  git,
  gnugrep,
  gnused,
  lib,
  nix,
  writeShellApplication,
}:
writeShellApplication {
  name = "maestro-bootstrap";
  runtimeInputs = [
    coreutils
    findutils
    git
    gnugrep
    gnused
    nix
  ];
  text = builtins.readFile ../bootstrap.sh;
  meta = {
    description = "Bootstrap the fixed Maestro appliance checkout";
    license = lib.licenses.asl20;
    mainProgram = "maestro-bootstrap";
    platforms = ["x86_64-linux"];
  };
}
