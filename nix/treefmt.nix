{inputs, ...}: {
  imports = [
    inputs.treefmt-nix.flakeModule
  ];

  perSystem = _: {
    treefmt.config = {
      projectRootFile = "flake.nix";
      settings = {
        global.excludes = [
          "LICENSE-*"
          "target/**"
          "result"
          "*.lock"
          "docs/**"
          "tests/fixtures/**"
        ];
      };

      programs = {
        deadnix.enable = true;
        alejandra.enable = true;
        statix.enable = true;
        rustfmt = {
          enable = true;
          edition = "2021";
        };
      };
    };
  };
}
