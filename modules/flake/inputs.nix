{...}: {
  flake-file.inputs = {
    flake-parts = {
      url = "github:hercules-ci/flake-parts/17c9d6cdfc60c64f4ee8d306f9bc0b4ccb51481e";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    flake-file.url = "github:vic/flake-file/7b08dbc223bb1a758a515aad9653a6bf196bc772";
    den.url = "github:denful/den/v0.16.0";
    devenv.url = "github:cachix/devenv";
    determinate.url = "https://flakehub.com/f/DeterminateSystems/determinate/*";
    # FlakeHub's /0 selectors track the latest stable release train. The /0.1
    # selectors are rolling and follow nixos-unstable.
    home-manager = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "https://flakehub.com/f/nix-community/home-manager/0";
    };
    import-tree.url = "github:vic/import-tree";
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0";
    # Pin the reviewed XO runtime and shared admission evaluator together.
    xen-orchestra-ce.url = "github:closure-labs/xo-nixpkg/cc71a6c82674a26557271b5d4e730e2f05a8cf03";
  };
}
