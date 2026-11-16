let
  xo = (import ../../../../.tack).xo-nixpkg;
in {
  inherit (xo) lib packages;
  inherit (xo.inputs) nixpkgs;
}
