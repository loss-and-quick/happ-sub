# The `happ-sub` library package built via crane.
_: {
  perSystem = {
    pkgs,
    craneLib,
    ...
  }: let
    # Cargo sources plus the data files crane's Cargo-only filter would drop: the embedded URL
    # keyring and the README (both `include_str!`), and the fixtures the integration tests read.
    src = pkgs.lib.cleanSourceWith {
      src = ../.;
      name = "source";
      filter = path: type:
        (craneLib.filterCargoSources path type)
        || (pkgs.lib.hasSuffix "/src/keys/url-keys.json" path)
        || (path == toString ../README.md)
        || (pkgs.lib.hasInfix "/tests/fixtures" path);
    };

    commonArgs = {
      inherit src;
      strictDeps = true;
      pname = "happ-sub";
      inherit ((craneLib.crateNameFromCargoToml {cargoToml = ../Cargo.toml;})) version;
    };

    cargoArtifacts = craneLib.buildDepsOnly commonArgs;

    happ-sub = craneLib.buildPackage (commonArgs
      // {
        inherit cargoArtifacts;
        meta = {
          description = "Happ-compatible subscription handling: body-form detection, meta protocol, AES-128-GCM, crypt1..5, routing and deeplinks";
          homepage = "https://github.com/loss-and-quick/happ-sub";
          license = with pkgs.lib.licenses; [mit asl20];
        };
      });

    happ-sub-doc = craneLib.cargoDoc (commonArgs
      // {
        inherit cargoArtifacts;
        cargoExtraArgs = "--all-features";
      });
  in {
    packages = {
      default = happ-sub;
      inherit happ-sub;
      doc = happ-sub-doc;
    };

    checks = {
      inherit happ-sub;

      clippy = craneLib.cargoClippy (commonArgs
        // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--all-targets --all-features -- -D warnings";
        });

      fmt = craneLib.cargoFmt {
        inherit src;
      };

      test = craneLib.cargoTest (commonArgs
        // {
          inherit cargoArtifacts;
          cargoTestExtraArgs = "--all-features";
        });
    };
  };
}
