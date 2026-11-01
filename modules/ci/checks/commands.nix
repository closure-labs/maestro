{config, ...}: {
  perSystem = {
    lib,
    maestroCi,
    ...
  }: {
    packages =
      lib.mapAttrs' (name: package: lib.nameValuePair "maestro-ci-${name}" package)
      (import ./_lib/commands.nix (maestroCi // {cacheConfig = config.flake-file.nixConfig;}));
  };
}
