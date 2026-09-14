{
  lib,
  stdenvNoCC,
  nodejs_24,
  makeWrapper,
}:

let
  packageJson = lib.importJSON ../package.json;
in
stdenvNoCC.mkDerivation {
  pname = "jaynshare";
  version = packageJson.version;

  src = lib.cleanSource ../.;

  nativeBuildInputs = [ makeWrapper ];

  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin $out/share/jaynshare
    cp -R package.json src LICENSE README.md config.example.json $out/share/jaynshare/
    chmod +x $out/share/jaynshare/src/index.js

    makeWrapper ${lib.getExe nodejs_24} $out/bin/jaynshare \
      --add-flags "$out/share/jaynshare/src/index.js" \
      --set-default JAYNSHARE_DISABLE_AUTOUPDATE 1

    runHook postInstall
  '';

  meta = {
    description = packageJson.description;
    homepage = packageJson.homepage;
    license = lib.licenses.mit;
    mainProgram = "jaynshare";
    platforms = nodejs_24.meta.platforms;
  };
}
