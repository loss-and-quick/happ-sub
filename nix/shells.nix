_: {
  perSystem = {
    pkgs,
    toolchain,
    ...
  }: let
    inherit (toolchain) nativeTools baseHook;
  in {
    devShells.default = pkgs.mkShell {
      nativeBuildInputs = nativeTools;
      shellHook = baseHook;
    };
  };
}
