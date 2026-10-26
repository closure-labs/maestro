{
  inputs,
  lib,
  ...
}: {
  perSystem = {
    pkgs,
    system,
    ...
  }: let
    packages = inputs.self.packages.${system};
    appliance = inputs.self.nixosConfigurations.maestro.config;
    fixtureInputs = [
      pkgs.bash
      pkgs.coreutils
      pkgs.findutils
      pkgs.git
      pkgs.gnugrep
      pkgs.gnused
      pkgs.jq
    ];
    mkSourceCheck = import ../checks/_lib/source-check.nix {inherit pkgs lib inputs packages fixtureInputs;};
  in {
    checks = {
      security-fixtures = mkSourceCheck {
        name = "security-fixtures";
        command = ''
          PYTHONDONTWRITEBYTECODE=1 python3 ./modules/ci/security/_tests/security-inventory.py
          PYTHONDONTWRITEBYTECODE=1 python3 ./modules/ci/security/_tests/security-components.py
          test -e ${inputs.self.checks.${system}.xo-file-restore-fixtures}
          test -e ${inputs.self.checks.${system}.xo-storage-fixtures}
          bash ./modules/ci/security/_tests/policy-drift.sh
          bash ./modules/ci/security/_tests/security-contracts.sh
          bash ./modules/ci/security/_tests/evidence-download.sh
          bash ./modules/ci/security/_tests/provenance-requests.sh
          bash ./modules/ci/security/_tests/security-scan.sh
          bash ./modules/ci/checks/_tests/codeql-rust-toolchain.sh ${lib.getExe packages.maestro-ci-codeql-rust-toolchain}
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/decision-observations.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_secret_inventory.py
          PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s modules/ci/authority/_tests/decisions -p '*.py'
          MAESTRO_TEST_PUBLISH_COMMAND=${lib.getExe packages.maestro-ci-publish} \
            MAESTRO_TEST_INSPECT_COMMAND=${lib.getExe packages.maestro-ci-publication-inspect} \
            PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_publish_readback.py
          MAESTRO_TEST_PUBLISH_COMMAND=${lib.getExe packages.maestro-ci-publish} \
            MAESTRO_TEST_INSPECT_COMMAND=${lib.getExe packages.maestro-ci-publication-inspect} \
            PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_readonly_preflight.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_cache_cancellation.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_cache_recovery.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_scheduling.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_operations.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_consumer_probe.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_consumer_result.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/release/publication/_tests/publication-journal.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_release_transaction.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_ci_admission.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/publication-diagnostics.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_request_attribution.py
          MAESTRO_TEST_LIBCURL=${pkgs.curl.out}/lib/libcurl.so.4 \
            MAESTRO_TEST_CURL=${pkgs.curl.bin}/bin/curl \
            MAESTRO_TEST_OPENSSL=${pkgs.openssl.bin}/bin/openssl \
            PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/test_public_cache_transport.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/checks/_tests/distribution-cache.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/graph/_tests/qualification-restore.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/features/installer/_tests/installer-coverage.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/decision-operations.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/authority/_tests/decision-only.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/checks/_tests/audit-diagnostics.py
          PYTHONDONTWRITEBYTECODE=1 python3 modules/ci/graph/_tests/qualification-diagnostics.py
        '';
        nativeBuildInputs = fixtureInputs ++ [pkgs.openssh pkgs.python3 pkgs.gitleaks pkgs.yq-go];
      };

      runtime-security = import ./_tests/runtime-security.nix {inherit pkgs inputs appliance;};
      secretspec-contract =
        pkgs.runCommandLocal "maestro-secretspec-contract" {
          nativeBuildInputs = [
            pkgs.jq
            pkgs.python3
            packages.secretspec
          ];
        } ''
          export HOME="$TMPDIR/home"
          mkdir -p "$HOME"
          SECRETSPEC_BIN=${inputs.devenv.packages.${system}.devenv}/bin/secretspec \
            PYTHONDONTWRITEBYTECODE=1 python3 ${inputs.self}/modules/ci/authority/_tests/test_cache_doctor.py
          secretspec schema --file ${inputs.self}/secretspec.toml \
            --profile development --output development-schema.json
          jq -e '[.properties | keys[] | select(test("TOKEN|PASSWORD|PEM|DECIDER_KEY"))] == []' \
            development-schema.json >/dev/null
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile github \
            --output github-schema.json
          jq -e '.required == ["CACHIX_MAESTRO_PUBKEY", "MAESTRO_DECISION_ONLY_REUSE_ENABLED", "MAESTRO_PACKET_METADATA_BATCH_ENABLED", "MAESTRO_PACKET_METADATA_REUSE_ENABLED", "MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED", "MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED", "MAESTRO_RELEASE_CONTINUATION_ENABLED", "MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS", "MAESTRO_RELEASE_TRANSACTION_ENABLED", "MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED"]' github-schema.json >/dev/null
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile github-queue \
            --output queue-schema.json
          jq -e '.required == ["CACHIX_MAESTRO_PUBKEY", "MAESTRO_DECISION_ONLY_REUSE_ENABLED", "MAESTRO_PACKET_METADATA_BATCH_ENABLED", "MAESTRO_PACKET_METADATA_REUSE_ENABLED", "MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED", "MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED", "MAESTRO_RELEASE_CONTINUATION_ENABLED", "MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS", "MAESTRO_RELEASE_TRANSACTION_ENABLED", "MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED", "MERGE_QUEUE_TOKEN"]' queue-schema.json >/dev/null
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile github-publish \
            --output publish-schema.json
          jq -e \
            '.required == ["CACHIX_MAESTRO_AUTH_TOKEN", "CACHIX_MAESTRO_PUBKEY", "MAESTRO_DECISION_ONLY_REUSE_ENABLED", "MAESTRO_PACKET_METADATA_BATCH_ENABLED", "MAESTRO_PACKET_METADATA_REUSE_ENABLED", "MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED", "MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED", "MAESTRO_RELEASE_CONTINUATION_ENABLED", "MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS", "MAESTRO_RELEASE_TRANSACTION_ENABLED", "MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED"]' \
            publish-schema.json >/dev/null
          secretspec schema \
            --file ${inputs.self}/secretspec.toml \
            --profile local-publish \
            --output local-schema.json
          jq -e \
            '.required == ["CACHIX_MAESTRO_AUTH_TOKEN", "CACHIX_MAESTRO_PUBKEY", "MAESTRO_DECISION_ONLY_REUSE_ENABLED", "MAESTRO_PACKET_METADATA_BATCH_ENABLED", "MAESTRO_PACKET_METADATA_REUSE_ENABLED", "MAESTRO_PUBLIC_CACHE_TRANSPORT_REUSE_ENABLED", "MAESTRO_READONLY_PUBLICATION_PREFLIGHT_ENABLED", "MAESTRO_RELEASE_CONTINUATION_ENABLED", "MAESTRO_RELEASE_RETIRED_REQUEST_RUN_IDS", "MAESTRO_RELEASE_TRANSACTION_ENABLED", "MAESTRO_RELEASE_VERIFICATION_REUSE_ENABLED"]' \
            local-schema.json >/dev/null
          touch "$out"
        '';
    };
  };
}
