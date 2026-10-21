{
  lib,
  stdenv,
  mkShell,
  cargo,
  clang,
  clippy,
  pkg-config,
  rustc,
  rustfmt,
  sqlite,
  wild,
}:
let
  hasWild =
    stdenv.hostPlatform.isLinux && (stdenv.hostPlatform.isx86_64 || stdenv.hostPlatform.isAarch64);
in
mkShell {
  packages = [
    cargo
    rustc
    rustfmt
    clippy
    pkg-config
    sqlite
  ]
  ++ lib.optionals hasWild [
    wild
    clang
  ];

  env = lib.optionalAttrs hasWild {
    RUSTFLAGS = "-Clinker=${clang}/bin/clang -Clink-arg=--ld-path=wild";
  };
}
