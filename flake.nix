{
  description = "Nix vulnerability scanning with CNA coverage";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      pkgsFor = system: nixpkgs.legacyPackages.${system} or (import nixpkgs { inherit system; });
      supportedSystems = lib.filter (
        system:
        let
          pkgs = pkgsFor system;
        in
        builtins.hasAttr system nixpkgs.legacyPackages
        && lib.meta.availableOn pkgs.stdenv.hostPlatform pkgs.rustPlatform.rust.rustc
      ) (lib.systems.doubles.linux ++ lib.systems.doubles.darwin);
      forAllSystems = lib.genAttrs supportedSystems;
    in
    {
      nixosModules.default = import ./nix/module.nix self;

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.callPackage ./nix/package.nix { };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.callPackage ./nix/shell.nix { };
        }
      );
    };
}
