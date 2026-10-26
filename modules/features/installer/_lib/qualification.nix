# SPDX-License-Identifier: Apache-2.0
# Internal qualification adapter, not another public NixOS configuration.
{
  lib,
  installerSystem,
  installerIso,
}: let
  c = installerSystem.config;
  pkgs = installerSystem.pkgs;
  rootOf = source: let
    value = toString source;
    matched = builtins.match "(/nix/store/[^/]+)(/.*)?" value;
  in
    assert lib.assertMsg (matched != null) "Installer content must have an immutable store origin";
    # substring retains the producing derivation's string context.
      builtins.substring 0 (builtins.stringLength (builtins.head matched)) value;
  isoRecipe = pkgs.path + "/nixos/modules/installer/cd-dvd/iso-image.nix";
  initrdRecipe = pkgs.path + "/pkgs/build-support/kernel/make-initrd-ng.nix";
  # These adapters describe copied/generated code, whose output deliberately
  # drops references. Recipe drift needs a reviewed attribution update.
  supported =
    builtins.hashFile "sha256" isoRecipe
    == "b20c923caca268694ceeff71aa844541219246625ee6feb30f9dc8af879e9490"
    && builtins.hashFile "sha256" initrdRecipe == "ec121f81e6e3e6e7c7ae0f394fdd2191721130730f8d30afd162343d4adc4833";
  contents = builtins.fromJSON (builtins.unsafeDiscardStringContext c.system.build.initialRamdisk.contentsJSON);
  initrdSources = map (entry: builtins.appendContext entry.source (builtins.getContext c.system.build.initialRamdisk.contentsJSON)) contents;
  isoBindings =
    map (entry: {
      kind = "iso-content";
      source = toString entry.source;
      destination = entry.target;
      root = rootOf entry.source;
    })
    c.isoImage.contents;
  # All effective initrd sources are runtime inputs. This does not traverse
  # build dependencies (cpio, compressors, compilers, grub-mkimage, etc.).
  initrdBindings =
    lib.imap0 (index: source: {
      kind = "initrd-content";
      inherit source;
      # make-initrd-ng preserves the source path; target, when present,
      # creates an additional symlink inside the archive.
      destination = source;
      alias = (builtins.elemAt contents index).target or null;
      root = rootOf source;
    })
    initrdSources;
  grubPkgs =
    if c.boot.loader.grub.forcei686
    then pkgs.pkgsi686Linux
    else pkgs;
  bootBindings =
    lib.optionals c.isoImage.makeBiosBootable [
      {
        kind = "bios-code";
        source = "${pkgs.syslinux}/share/syslinux";
        destination = "/isolinux";
        root = pkgs.syslinux.outPath;
      }
    ]
    ++ lib.optionals c.isoImage.makeEfiBootable [
      {
        kind = "efi-code";
        source = "${grubPkgs.grub2_efi}/lib/grub/${grubPkgs.grub2_efi.grubTarget}";
        destination = "/EFI/BOOT/BOOTX64.EFI";
        root = grubPkgs.grub2_efi.outPath;
      }
      {
        kind = "efi-code";
        source = "${pkgs.refind}/share/refind/refind_x64.efi";
        destination = "/EFI/BOOT/refind_x64.efi";
        root = pkgs.refind.outPath;
      }
    ];
  # ISO content origins include the kernel, initrd, memtest, generated EFI
  # images, and data. Keep exact origins, not a guessed list of packages.
  paths =
    lib.unique ([c.system.build.toplevel.outPath]
      ++ map (entry: entry.root) (isoBindings ++ initrdBindings ++ bootBindings));
  roots = builtins.listToAttrs (lib.imap0 (index: path: {
      name = "installer-${toString index}";
      value = path;
    })
    paths);
  passwordState = user: let
    values = lib.filter (value: value != null) [user.hashedPassword user.initialHashedPassword user.password user.initialPassword];
  in
    if user.hashedPasswordFile != null
    then "configured"
    else if values == []
    then "absent"
    else if builtins.elem "" values
    then "empty"
    else if builtins.any (value: !(builtins.elem value ["!" "*"])) values
    then "configured"
    else "locked";
in
  assert lib.assertMsg supported "Installer boot recipes changed: review copied native-code provenance";
  assert lib.assertMsg (c.boot.initrd.systemd.enable && c.boot.initrd.prepend == [] && c.specialisation == {}) "Installer qualification supports systemd initrd without prepend archives or specialisations";
  assert lib.assertMsg (pkgs.stdenv.hostPlatform.system == "x86_64-linux") "Installer boot attribution is x86_64-only"; {
    inherit roots;
    schema = 1;
    iso = installerIso.outPath;
    system = c.system.build.toplevel.outPath;
    bindings = isoBindings ++ initrdBindings ++ bootBindings;
    recipes = {
      iso = builtins.hashFile "sha256" isoRecipe;
      initrd = builtins.hashFile "sha256" initrdRecipe;
    };
    policy = {
      ssh = c.services.openssh.settings;
      firewall = {
        inherit (c.networking.firewall) allowedTCPPorts allowedUDPPorts extraCommands;
      };
      sudo = {inherit (c.security.sudo) enable wheelNeedsPassword extraRules;};
      operator = {
        inherit (c.users.users.maestro) extraGroups;
        passwordState = passwordState c.users.users.maestro;
        rootPasswordState = passwordState c.users.users.root;
        inherit (c.users) mutableUsers;
      };
      systemdInitrd = c.boot.initrd.systemd.enable;
      bootModes = {
        bios = c.isoImage.makeBiosBootable;
        efi = c.isoImage.makeEfiBootable;
        memtest = c.boot.loader.grub.memtest86.enable;
      };
      bootPolicy = {
        kernelParams = c.boot.kernelParams;
        emergencyMode = c.systemd.enableEmergencyMode;
        initrdEmergencyAccess = let
          value = c.boot.initrd.systemd.emergencyAccess;
        in
          if value == false || value == null
          then "disabled"
          else if value == true || value == ""
          then "unauthenticated"
          else if builtins.elem value ["!" "*"]
          then "locked"
          else "configured";
      };
    };
  }
