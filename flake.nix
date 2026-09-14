{
  description = "Jaynshare packaged as a dependency-free Node application";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems =
        f:
        builtins.listToAttrs (
          map (system: {
            name = system;
            value = f system;
          }) systems
        );
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          jaynshare = pkgs.callPackage ./nix/package.nix { };
        in
        {
          inherit jaynshare;
          default = jaynshare;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          # `nix flake check` builds the package on every system.
          package = self.packages.${system}.jaynshare;
        }
        # The NixOS VM test only runs on Linux (nixosTest requires a Linux host).
        // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          nixos-module = import ./nix/tests/module.nix { inherit pkgs self system; };
        }
      );

      apps = forAllSystems (system: {
        jaynshare = {
          type = "app";
          program = "${self.packages.${system}.jaynshare}/bin/jaynshare";
          meta = {
            inherit (self.packages.${system}.jaynshare.meta) description;
          };
        };
        default = self.apps.${system}.jaynshare;
      });

      nixosModules = {
        jaynshare = import ./nix/module.nix;
        default = self.nixosModules.jaynshare;
      };

      homeManagerModules = {
        jaynshare = import ./nix/home-manager-module.nix;
        default = self.homeManagerModules.jaynshare;
      };
    };
}
