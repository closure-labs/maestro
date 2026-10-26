{...}: {
  perSystem = {pkgs, ...}: {
    packages.metadata = pkgs.stdenv.mkDerivation {
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
  };
}
