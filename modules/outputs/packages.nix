{
  inputs,
  lib,
  ...
}: let
  systems = ["x86_64-linux"];
in {
  flake.packages = lib.genAttrs systems (
    system: let
      pkgs = import inputs.nixpkgs {
        inherit system;
        config.allowUnfreePredicate = package:
          lib.getName package == "packer";
      };
      xenOrchestraCe = inputs.xen-orchestra-ce.packages.x86_64-linux.latest;
      xenOrchestraSupplyProtector = inputs.xen-orchestra-ce.packages.x86_64-linux.supply-protector-latest;
      planRunner = inputs.xen-orchestra-ce.packages.${system}.flake-plan-runner;
      maestroctl = pkgs.callPackage ../../pkgs/maestroctl/package.nix {};
      maestroMenu = pkgs.callPackage ../../pkgs/maestro-menu/package.nix {};
      automationCommands = import ../../nix/automation {
        inherit pkgs planRunner packerXenserver;
        appliance = inputs.self.nixosConfigurations.maestro.config;
        lockFile = ../../flake.lock;
        packageSourceRoots = [inputs.nixpkgs.outPath inputs.xen-orchestra-ce.inputs.nixpkgs.outPath];
      };
      automationPackages =
        lib.mapAttrs' (
          name: package: lib.nameValuePair "maestro-ci-${name}" package
        )
        automationCommands;
      secretspec = pkgs.callPackage ../../nix/pkgs/secretspec.nix {};
      packerXenserverPlugin = pkgs.callPackage ../../pkgs/packer-xenserver-plugin/package.nix {};
      packerXenserver = pkgs.callPackage ../../pkgs/packer-xenserver/package.nix {
        inherit packerXenserverPlugin;
      };
      bootstrap = pkgs.callPackage ../../pkgs/maestro-bootstrap/package.nix {};
      templateTools = pkgs.callPackage ../../pkgs/maestro-template-tools/package.nix {
        inherit packerXenserver;
        qualificationValidation = [automationCommands.download-installer];
      };
      applianceToplevel = inputs.self.nixosConfigurations.maestro.config.system.build.toplevel;
      installerSystem = inputs.nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [../../installer];
        specialArgs = {
          inherit applianceToplevel maestroMenu xenOrchestraCe;
        };
      };
      installerIso = assert builtins.elem applianceToplevel installerSystem.config.isoImage.storeContents;
      assert builtins.elem maestroMenu installerSystem.config.isoImage.storeContents;
      assert builtins.elem xenOrchestraCe installerSystem.config.isoImage.storeContents;
        installerSystem.config.system.build.isoImage;
    in
      {
        xen-orchestra-ce = xenOrchestraCe;
        xen-orchestra-supply-protector = xenOrchestraSupplyProtector;
        flake-plan-runner = planRunner;
        sbomnix = pkgs.sbomnix;
        inherit secretspec;
        libvhdi = inputs.xen-orchestra-ce.packages.x86_64-linux.libvhdi;
        default = xenOrchestraCe;
      }
      // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
        {
          inherit bootstrap;
          build-template = templateTools.build;
          deploy-template = templateTools.deploy;
          maestroctl = maestroctl;
          maestro-menu = maestroMenu;
        }
        // automationPackages
      )
      // {
        installer-iso = installerIso;
        metadata = pkgs.stdenv.mkDerivation {
          pname = "maestro-metadata";
          version = "3.1.0";
          dontUnpack = true;
          dontBuild = true;
          installPhase = ''
            mkdir -p $out/share/doc/maestro
            echo "Maestro - Xen Orchestra Community Edition on NixOS" > $out/share/doc/maestro/README
            echo "This flake defines the single maestro XCP-ng appliance." >> $out/share/doc/maestro/README
            echo "See https://github.com/closure-labs/maestro for details." >> $out/share/doc/maestro/README
          '';
          meta = with pkgs.lib; {
            description = "Xen Orchestra Community Edition appliance for XCP-ng";
            homepage = "https://github.com/closure-labs/maestro";
            license = licenses.asl20;
            maintainers = [
              {
                name = "Dale Morgan";
                codeberg = "dalemorgan";
              }
            ];
            platforms = platforms.linux;
          };
        };
      }
  );
}
