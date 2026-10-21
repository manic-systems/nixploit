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

  postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    installShellCompletion --cmd nixploit          \
      --bash    <(COMPLETE=bash $out/bin/nixploit) \
      --fish    <(COMPLETE=fish $out/bin/nixploit) \
      --zsh     <(COMPLETE=zsh  $out/bin/nixploit) \
      --nushell <(COMPLETE=nu   $out/bin/nixploit)
  '';

  env = lib.optionalAttrs hasWild {
    RUSTFLAGS = "-Clinker=${clang}/bin/${clang.targetPrefix}clang -Clink-arg=--ld-path=wild";
  };

  meta.mainProgram = "nixploit";
}
