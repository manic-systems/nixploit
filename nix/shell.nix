{
  lib,
  stdenv,
  mkShell,
  cargo,
  clang,
  clippy,
  rustc,
  rustfmt,
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
  ]
  ++ lib.optionals hasWild [
    wild
    clang
  ];

  env = lib.optionalAttrs hasWild {
    RUSTFLAGS = "-Clinker=${clang}/bin/clang -Clink-arg=--ld-path=wild";
  };
}
