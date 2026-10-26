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
  publication-inspect = mkCommand {
    name = "publication-inspect";
    prefix = ''
      export PUBLICATION_DESTINATIONS_SOURCE=${../../../ci/authority/_source/decisions}/destinations.py
      export PUBLICATION_CURL_WORKER_SOURCE=${publicCacheWorker}
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.curl];
    source = ../../../ci/authority/_source/publication-inspect.sh;
  };
  publication-diagnostics = mkCommand {
    name = "publication-diagnostics";
    prefix = ''
      export MAESTRO_DECISIONS_SOURCE=${../../../ci/authority/_source/decisions}
    '';
    runtimeInputs = [pkgs.python3];
    source = ../../../ci/authority/_source/publication-diagnostics.sh;
  };
  publication-journal = mkCommand {
    name = "publication-journal";
    prefix = ''
      MAESTRO_DECISIONS_SOURCE=${../../../ci/authority/_source/decisions}
      MAESTRO_PUBLICATION_JOURNAL_SOURCE=${../../../ci/authority/_source/publication-journal.py}
      MAESTRO_PUBLICATION_ASSETS_SOURCE=${../../../ci/authority/_source/publication-assets.py}
      export MAESTRO_DECISIONS_SOURCE MAESTRO_PUBLICATION_JOURNAL_SOURCE MAESTRO_PUBLICATION_ASSETS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras];
    source = ../../../ci/authority/_source/publication-journal.sh;
  };
  release-reservation = mkCommand {
    name = "release-reservation";
    prefix = ''
      export MAESTRO_DECISIONS_SOURCE=${../../../ci/authority/_source/decisions}
      export MAESTRO_PUBLICATION_JOURNAL_SOURCE=${../../../ci/authority/_source/publication-journal.py}
      export MAESTRO_PUBLICATION_ASSETS_SOURCE=${../../../ci/authority/_source/publication-assets.py}
      export MAESTRO_RELEASE_COMPLETION_SOURCE=${../../../ci/authority/_source/release-completion.py}
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras commands.decision-handoff];
    source = ../../../ci/authority/_source/release-reservation.sh;
  };
  release-completion = mkCommand {
    name = "release-completion";
    prefix = ''
      export MAESTRO_DECISIONS_SOURCE=${../../../ci/authority/_source/decisions}
      export MAESTRO_PUBLICATION_JOURNAL_SOURCE=${../../../ci/authority/_source/publication-journal.py}
      export MAESTRO_PUBLICATION_ASSETS_SOURCE=${../../../ci/authority/_source/publication-assets.py}
      export MAESTRO_RELEASE_COMPLETION_SOURCE=${../../../ci/authority/_source/release-completion.py}
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras commands.decision-handoff];
    source = ../../../ci/authority/_source/release-completion.sh;
  };
  publication-assets = mkCommand {
    name = "publication-assets";
    prefix = ''
      MAESTRO_DECISIONS_SOURCE=${../../../ci/authority/_source/decisions}
      MAESTRO_PUBLICATION_JOURNAL_SOURCE=${../../../ci/authority/_source/publication-journal.py}
      MAESTRO_PUBLICATION_ASSETS_SOURCE=${../../../ci/authority/_source/publication-assets.py}
      export MAESTRO_DECISIONS_SOURCE MAESTRO_PUBLICATION_JOURNAL_SOURCE MAESTRO_PUBLICATION_ASSETS_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3 pkgs.oras commands.decision-handoff];
    source = ../../../ci/authority/_source/publication-assets.sh;
  };
  release-retain = mkCommand {
    name = "release-retain";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/release-retain.sh;
  };
  release-attestations = mkCommand {
    name = "release-attestations";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/release-attestations.sh;
  };
  release-request = mkCommand {
    name = "release-request";
    prefix = ''
      MAESTRO_RELEASE_REQUEST_SOURCE=${../../../ci/authority/_source/release-request.py}
      export MAESTRO_RELEASE_REQUEST_SOURCE
    '';
    runtimeInputs = commonInputs ++ [pkgs.python3];
    source = ../../../ci/authority/_source/release-request.sh;
  };
  publish = mkCommand {
    name = "publish";
    prefix = ''
      export PUBLICATION_DESTINATIONS_SOURCE=${../../../ci/authority/_source/decisions}/destinations.py
      export PUBLICATION_CURL_WORKER_SOURCE=${publicCacheWorker}
      export PUBLICATION_PREFLIGHT_SOURCE=${../../../ci/authority/_source/decisions}/publication_preflight.py
    '';
    runtimeInputs = commonInputs ++ [pkgs.cachix pkgs.python3 pkgs.curl commands.decision-publication commands.distribution-restore commands.decision-handoff];
    source = ../../../ci/authority/_source/publish.sh;
  };
  release-manager = mkCommand {
    name = "release-manager";
    runtimeInputs =
      commonInputs
      ++ [
        pkgs.gzip
        commands.qualification-inputs
        commands.release-notes
        commands.release-stage
        commands.release-version
        commands.publication-assets
        commands.trusted-update
        commands.validate-state
        commands.verify-inventory
        commands.trusted-run
      ];
    source = ../../../ci/authority/_source/release-manager.sh;
  };
  release-notes = mkCommand {
    name = "release-notes";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/release-notes.sh;
  };
  release-stage = mkCommand {
    name = "release-stage";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/release-split.sh;
  };
  release-version = mkCommand {
    name = "release-version";
    runtimeInputs = commonInputs;
    source = ../../../ci/authority/_source/release-version.sh;
  };
}
