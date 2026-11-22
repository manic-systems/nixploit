{
  lib,
  rustPlatform,
  stdenv,
  buildPackages,
  installShellFiles,
  pkg-config,
  sqlite,
}:
let
  inherit (buildPackages) clang wild;
  hasWild =
    stdenv.hostPlatform.isLinux && (stdenv.hostPlatform.isx86_64 || stdenv.hostPlatform.isAarch64);
in
rustPlatform.buildRustPackage {
  pname = "nixploit";
  version = (lib.importTOML ../Cargo.toml).package.version;
  src = ../.;
  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = [
    installShellFiles
    pkg-config
  ]
  ++ lib.optionals hasWild [
    wild
    clang
  ];

  buildInputs = [ sqlite ];

  postInstall = lib.optionalString (stdenv.hostPlatform.emulatorAvailable buildPackages) (
    let
      nixploit = "${stdenv.hostPlatform.emulator buildPackages} $out/bin/nixploit";
    in
    ''
      installShellCompletion --cmd nixploit \
        --bash    <(COMPLETE=bash ${nixploit}) \
        --zsh     <(COMPLETE=zsh  ${nixploit}) \
        --fish    <(COMPLETE=fish ${nixploit}) \
        --nushell <(COMPLETE=nu   ${nixploit})
    ''
  );

  env = lib.optionalAttrs hasWild {
    RUSTFLAGS = "-Clinker=${clang}/bin/${clang.targetPrefix}clang -Clink-arg=--ld-path=wild";
  };

  meta.mainProgram = "nixploit";
}
