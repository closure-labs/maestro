{pkgs}: let
  secretspec = pkgs.callPackage ./pkgs/secretspec.nix {};
in [
  pkgs.actionlint
  pkgs.alejandra
  pkgs.cargo
  pkgs.clippy
  pkgs.gh
  pkgs.gitleaks
  pkgs.oras
  pkgs.python3
  pkgs.git
  pkgs.jq
  pkgs.nixd
  pkgs.packer
  pkgs.rust-analyzer
  pkgs.rustc
  pkgs.rustfmt
  secretspec
  pkgs.shellcheck
  pkgs.zizmor
  pkgs.yq-go
]
