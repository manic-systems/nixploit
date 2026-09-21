{
  lib,
  rustPlatform,
  stdenv,
  clang,
  wild,
}:
let
  hasWild =
    stdenv.hostPlatform.isLinux && (stdenv.hostPlatform.isx86_64 || stdenv.hostPlatform.isAarch64);
in
rustPlatform.buildRustPackage {
  pname = "nixploit";
  version = (lib.importTOML ../Cargo.toml).package.version;
  src = ../.;
  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = lib.optionals hasWild [
    wild
    clang
  ];

  env = lib.optionalAttrs hasWild {
    RUSTFLAGS = "-Clinker=${clang}/bin/clang -Clink-arg=--ld-path=wild";
  };

  meta.mainProgram = "nixploit";
}
