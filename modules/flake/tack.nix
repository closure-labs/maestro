{...}: {
  perSystem = {system, ...}: {
    packages.tack = (import ../../.tack).tack.packages.${system}.tack;
  };
}
