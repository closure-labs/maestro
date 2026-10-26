{
  pkgs,
  planRunner,
  packerXenserver,
  ciNix,
  appliance,
  lockFile,
  packageSourceRoots,
  applicabilityCommand,
  distributionRoots,
  installerQualification,
  devenv,
  commands,
  common,
}: let
  inherit (common) mkCommand commonInputs spdxSchema boundedGh publicCacheWorker validatePlan classifyPaths;
in {
  cache-doctor = mkCommand {
    name = "cache-doctor";
    prefix = ''
      export PYTHONPATH=${../../../ci/authority/_source/decisions}
      export MAESTRO_CACHE_DOCTOR_SOURCE=${../../../ci/authority/_source/cache-doctor.py}
    '';
    runtimeInputs = [pkgs.python3 devenv];
    source = ../../../ci/authority/_source/cache-doctor.sh;
  };
  codeql-rust-toolchain = let
    toolchain = pkgs.runCommand "maestro-codeql-rust-toolchain" {} ''
      mkdir -p "$out/bin" "$out/lib/rustlib/src/rust"
      ln -s ${pkgs.cargo}/bin/cargo "$out/bin/cargo"
      ln -s ${pkgs.rustc}/bin/rustc "$out/bin/rustc"
      ln -s ${pkgs.rustc}/bin/rustdoc "$out/bin/rustdoc"
      ln -s ${pkgs.rustPlatform.rustLibSrc} "$out/lib/rustlib/src/rust/library"
    '';
  in
    mkCommand {
      name = "codeql-rust-toolchain";
      prefix = ''
        MAESTRO_CODEQL_RUST_TOOLCHAIN=${toolchain}
        MAESTRO_CODEQL_RUSTUP=${pkgs.rustup}/bin/rustup
        MAESTRO_CODEQL_RUST_SRC=${pkgs.rustPlatform.rustLibSrc}
        export MAESTRO_CODEQL_RUST_TOOLCHAIN MAESTRO_CODEQL_RUSTUP MAESTRO_CODEQL_RUST_SRC
      '';
      runtimeInputs = commonInputs ++ [pkgs.rustup];
      source = ../../../ci/authority/_source/codeql-rust-toolchain.sh;
    };
  fix-hashes = mkCommand {
    name = "fix-hashes";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/fix-hashes.sh;
  };
  lock-validate = mkCommand {
    name = "lock-validate";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/lock-validate.sh;
  };
  open-update-pr = mkCommand {
    name = "open-update-pr";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/open-update-pr.sh;
  };
  trusted-update = mkCommand {
    name = "trusted-update";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/trusted-update.sh;
  };
  update-locks = mkCommand {
    name = "update-locks";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/update-locks.sh;
  };
}
