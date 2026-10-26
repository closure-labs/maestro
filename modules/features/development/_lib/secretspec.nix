{
  autoPatchelfHook,
  dbus,
  fetchurl,
  lib,
  openssl,
  stdenv,
  stdenvNoCC,
}:
stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "secretspec";
  version = "0.19.1";

  src = fetchurl {
    url = "https://github.com/cachix/secretspec/releases/download/v${finalAttrs.version}/secretspec-x86_64-unknown-linux-gnu.tar.xz";
    hash = "sha256-mgtYglMvX/uxxofZKE+oBBlJlisF8U/BMQUPhscOHvw=";
  };

  sourceRoot = "secretspec-x86_64-unknown-linux-gnu";
  nativeBuildInputs = [autoPatchelfHook];
  buildInputs = [
    dbus
    openssl
    stdenv.cc.cc.lib
  ];

  installPhase = ''
    runHook preInstall
    install -Dm755 secretspec "$out/bin/secretspec"
    runHook postInstall
  '';

  meta = {
    description = "Declarative interface for secret providers";
    homepage = "https://secretspec.dev";
    license = lib.licenses.asl20;
    mainProgram = "secretspec";
    platforms = ["x86_64-linux"];
  };
})
