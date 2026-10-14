# SPDX-License-Identifier: Apache-2.0
{
  pkgs,
  ciNix,
}:
# The pinned recipe selects nixVersions.nix_2_31 directly, so overriding its
# `nix` argument does not change the runtime. Replace only that version slot and
# reject recipe drift rather than silently returning to a different CLI.
let
  oldPath = "${pkgs.nixVersions.nix_2_31}/bin";
  countPath = path: arguments:
    builtins.foldl' (count: argument:
      count + builtins.length (pkgs.lib.splitString (builtins.unsafeDiscardStringContext path) argument) - 1)
    0
    arguments;
  runtimeAligned = pkgs.sbomnix.override {
    nixVersions = pkgs.nixVersions // {nix_2_31 = ciNix;};
  };
  aligned = runtimeAligned.overrideAttrs (previous: {
    patches = (previous.patches or []) ++ [./sbomnix-materialize-metadata.patch];
  });
in
  assert pkgs.lib.assertMsg (countPath oldPath pkgs.sbomnix.makeWrapperArgs == 1) "Review sbomnix's Nix runtime wrapper: expected exactly one pinned PATH entry";
  assert pkgs.lib.assertMsg (countPath "${ciNix}/bin" aligned.makeWrapperArgs == 1 && countPath oldPath aligned.makeWrapperArgs == 0) "sbomnix did not select the captured Nix adapter"; aligned
