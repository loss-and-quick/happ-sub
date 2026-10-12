{
  description = "happ-sub — standalone Rust library for Happ-compatible subscription handling";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    crane.url = "github:ipetkov/crane";
  };

  outputs = {flake-parts, ...} @ inputs: let
    flakeOutputs = flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];

      perSystem = {system, ...}: let
        pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [inputs.rust-overlay.overlays.default];
        };
        toolchain = import ./nix/toolchain.nix {inherit pkgs;};
        craneLib = (inputs.crane.mkLib pkgs).overrideToolchain toolchain.rustToolchain;
      in {
        _module.args = {
          inherit pkgs toolchain craneLib;
        };
      };

      imports = [
        ./nix/shells.nix
        ./nix/treefmt.nix
        ./nix/package.nix
      ];
    };
  in
    flakeOutputs;
}
