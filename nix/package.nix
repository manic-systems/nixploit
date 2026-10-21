{
  lib,
  rustPlatform,
  stdenv,
  buildPackages,
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
    pkg-config
  ]
  ++ lib.optionals hasWild [
    wild
    clang
  ];

  buildInputs = [ sqlite ];

  env = lib.optionalAttrs hasWild {
    RUSTFLAGS = "-Clinker=${clang}/bin/${clang.targetPrefix}clang -Clink-arg=--ld-path=wild";
  };

  meta.mainProgram = "nixploit";
}
