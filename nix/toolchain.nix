# Shared toolchain + native-dependency set derived from `pkgs`.
{pkgs}: let
  rustToolchain =
    (pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml).override
    (old: {
      extensions = (old.extensions or []) ++ ["rust-src"];
    });

  rustTools = [
    rustToolchain
    pkgs.rust-analyzer
  ];

  nativeTools = rustTools;
  baseHook = ''
    export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
    export RUST_SRC_PATH="${rustToolchain}/lib/rustlib/src/rust/library"
  '';
in {
  inherit nativeTools baseHook rustToolchain;
}
