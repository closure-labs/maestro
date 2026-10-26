{
  pkgs,
  lib,
  inputs,
  packages,
  fixtureInputs,
}: {
  name,
  command,
  nativeBuildInputs ? fixtureInputs,
  source ? inputs.self,
}:
pkgs.runCommandLocal "maestro-${name}" {inherit nativeBuildInputs;} ''
  cp -R ${source} source
  chmod -R u+w source
  cd source
  export HOME="$TMPDIR/home"
  export MAESTRO_CI_BOOT_MEDIA=${lib.getExe packages.maestro-ci-boot-media}
  export MAESTRO_CI_QUALIFICATION_INPUTS=${lib.getExe packages.maestro-ci-qualification-inputs}
  export MAESTRO_CI_CLASSIFY=${lib.getExe packages.maestro-ci-classify}
  export MAESTRO_CI_CACHE_VALIDATION=${lib.getExe packages.maestro-ci-cache-validation}
  export MAESTRO_CI_CLASSIFY_PATHS=${lib.getExe packages.maestro-ci-classify-paths}
  export MAESTRO_CI_VERDICT=${lib.getExe packages.maestro-ci-verdict}
  export MAESTRO_CI_LOCK_VALIDATE=${lib.getExe packages.maestro-ci-lock-validate}
  export MAESTRO_CI_ROUTE=${lib.getExe packages.maestro-ci-route}
  export MAESTRO_CI_RESOLVE_QUALIFICATION=${lib.getExe packages.maestro-ci-resolve-qualification}
  export MAESTRO_CI_RELEASE_MANAGER=${lib.getExe packages.maestro-ci-release-manager}
  export MAESTRO_CI_RELEASE_ATTESTATIONS=${lib.getExe packages.maestro-ci-release-attestations}
  export MAESTRO_CI_RELEASE_NOTES=${lib.getExe packages.maestro-ci-release-notes}
  export MAESTRO_CI_RELEASE_SPLIT=${lib.getExe packages.maestro-ci-release-stage}
  export MAESTRO_CI_RELEASE_VERSION=${lib.getExe packages.maestro-ci-release-version}
  export MAESTRO_CI_TRUSTED_UPDATE=${lib.getExe packages.maestro-ci-trusted-update}
  export MAESTRO_CI_OPEN_UPDATE_PR=${lib.getExe packages.maestro-ci-open-update-pr}
  export MAESTRO_CI_QUALIFICATION_CACHE=${lib.getExe packages.maestro-ci-qualification-cache}
  export MAESTRO_CI_VALIDATE_STATE=${lib.getExe packages.maestro-ci-validate-state}
  export MAESTRO_CI_TRUSTED_RUN=${lib.getExe packages.maestro-ci-trusted-run}
  export MAESTRO_CI_VERIFY_INVENTORY=${lib.getExe packages.maestro-ci-verify-inventory}
  export MAESTRO_CI_VERIFY_STATE=${lib.getExe packages.maestro-ci-verify-state}
  export MAESTRO_CI_DOWNLOAD_INSTALLER=${lib.getExe packages.maestro-ci-download-installer}
  export MAESTRO_CI_SECURITY_SCAN=${lib.getExe packages.maestro-ci-security-scan}
  export MAESTRO_CI_SECURITY_VERDICT=${lib.getExe packages.maestro-ci-security-verdict}
  export MAESTRO_SYSTEM_ROOT="$PWD"
  mkdir -p "$HOME"
  ${command}
  touch "$out"
''
