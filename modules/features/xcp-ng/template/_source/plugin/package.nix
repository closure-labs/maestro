# SPDX-License-Identifier: Apache-2.0
{
  buildGoModule,
  fetchFromGitHub,
  lib,
}: let
  version = "0.11.4";
in
  buildGoModule {
    pname = "packer-plugin-xenserver";
    inherit version;

    src = fetchFromGitHub {
      owner = "vatesfr";
      repo = "packer-plugin-xenserver";
      rev = "v${version}";
      hash = "sha256-RhoyP5f4z5vQ3hkj2ks4v6rZW9osGSnUJ0+KrntKvTk=";
    };

    vendorHash = "sha256-hKLvTZQzH5xjjhyVczN1XQN1Zx4o0rujhPJnbeSHm+M=";

    subPackages = ["."];
    ldflags = [
      "-s"
      "-w"
      "-X github.com/xenserver/packer-builder-xenserver/version.Version=v${version}"
      "-X github.com/xenserver/packer-builder-xenserver/version.VersionPrerelease="
    ];

    postInstall = ''
      mv "$out/bin/packer-builder-xenserver" \
        "$out/bin/packer-plugin-xenserver"
    '';

    meta = {
      description = "Packer plugin for XCP-ng and Citrix Hypervisor";
      homepage = "https://github.com/vatesfr/packer-plugin-xenserver";
      license = lib.licenses.mpl20;
      mainProgram = "packer-plugin-xenserver";
      platforms = lib.platforms.unix;
    };
  }
